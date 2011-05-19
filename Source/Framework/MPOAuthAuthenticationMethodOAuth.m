//
//  MPOAuthAuthenticationMethodOAuth.m
//  MPOAuthConnection
//
//  Created by Karl Adam on 09.12.19.
//  Copyright 2009 matrixPointer. All rights reserved.
//

#import "MPOAuthAuthenticationMethodOAuth.h"
#import "MPOAuthAPI.h"
#import "MPOAuthAPIRequestLoader.h"
#import "MPOAuthURLResponse.h"
#import "MPOAuthCredentialStore.h"
#import "MPOAuthCredentialConcreteStore.h"
#import "MPURLRequestParameter.h"

#import "NSURL+MPURLParameterAdditions.h"

NSString * const MPOAuthRequestTokenURLKey					= @"MPOAuthRequestTokenURL";
NSString * const MPOAuthUserAuthorizationURLKey				= @"MPOAuthUserAuthorizationURL";
NSString * const MPOAuthUserAuthorizationMobileURLKey		= @"MPOAuthUserAuthorizationMobileURL";

NSString * const MPOAuthCredentialRequestTokenKey			= @"oauth_token_request";
NSString * const MPOAuthCredentialRequestTokenSecretKey		= @"oauth_token_request_secret";
NSString * const MPOAuthCredentialAccessTokenKey			= @"oauth_token_access";
NSString * const MPOAuthCredentialAccessTokenSecretKey		= @"oauth_token_access_secret";
NSString * const MPOAuthCredentialSessionHandleKey			= @"oauth_session_handle";
NSString * const MPOAuthCredentialVerifierKey				= @"oauth_verifier";

@interface MPOAuthAPI ()
@property (nonatomic, readwrite, assign) MPOAuthAuthenticationState authenticationState;
@end


@interface MPOAuthAuthenticationMethodOAuth ()
@property (nonatomic, readwrite, assign) BOOL oauth10aModeActive;

- (void)_authenticationRequestForRequestToken;
- (void)_authenticationRequestForUserPermissionsConfirmationAtURL:(NSURL *)inURL;
- (void)_authenticationRequestForAccessToken;

@end

@implementation MPOAuthAuthenticationMethodOAuth

- (id)initWithAPI:(MPOAuthAPI *)inAPI forURL:(NSURL *)inURL withConfiguration:(NSDictionary *)inConfig {
	if (self = [super initWithAPI:inAPI forURL:inURL withConfiguration:inConfig]) {
		
		NSAssert( [inConfig count] >= 3, @"Incorrect number of oauth authorization methods");
		self.oauthRequestTokenURL = [NSURL URLWithString:[inConfig objectForKey:MPOAuthRequestTokenURLKey]];
		self.oauthAuthorizeTokenURL = [NSURL URLWithString:[inConfig objectForKey:MPOAuthUserAuthorizationURLKey]];
		self.oauthGetAccessTokenURL = [NSURL URLWithString:[inConfig objectForKey:MPOAuthAccessTokenURLKey]];		
		
/*		[[NSNotificationCenter defaultCenter] addObserver:self selector:@selector(_requestTokenReceived:) name:MPOAuthNotificationRequestTokenReceived object:nil];
		[[NSNotificationCenter defaultCenter] addObserver:self selector:@selector(_requestTokenRejected:) name:MPOAuthNotificationRequestTokenRejected object:nil];
		[[NSNotificationCenter defaultCenter] addObserver:self selector:@selector(_accessTokenReceived:) name:MPOAuthNotificationAccessTokenReceived object:nil];		*/
	}
	return self;
}

- (oneway void)dealloc {
	[[NSNotificationCenter defaultCenter] removeObserver:self];
	
	self.oauthRequestTokenURL = nil;
	self.oauthAuthorizeTokenURL = nil;

	[super dealloc];
}

@synthesize delegate = delegate_;
@synthesize oauthRequestTokenURL = oauthRequestTokenURL_;
@synthesize oauthAuthorizeTokenURL = oauthAuthorizeTokenURL_;
@synthesize oauth10aModeActive = oauth10aModeActive_;

#pragma mark -

- (void)authenticate {
	id <MPOAuthCredentialStore> credentials = [self.oauthAPI credentials];
	
	if (!credentials.accessToken && !credentials.requestToken) {
		[self _authenticationRequestForRequestToken];
	} else if (!credentials.accessToken) {
		[self _authenticationRequestForAccessToken];
	} else if (credentials.accessToken && [[NSUserDefaults standardUserDefaults] objectForKey:MPOAuthTokenRefreshDateDefaultsKey]) {
		NSTimeInterval expiryDateInterval = [[NSUserDefaults standardUserDefaults] doubleForKey:MPOAuthTokenRefreshDateDefaultsKey];
		NSDate *tokenExpiryDate = [NSDate dateWithTimeIntervalSinceReferenceDate:expiryDateInterval];
			
		if ([tokenExpiryDate compare:[NSDate date]] == NSOrderedAscending) {
			[self refreshAccessToken];
		}
	} else if (credentials.accessToken) {
        [self.oauthAPI setAuthenticationState:MPOAuthAuthenticationStateAuthenticated];
    }
}

- (void)_authenticationRequestForRequestToken {
	if (self.oauthRequestTokenURL) {
		MPLog(@"--> Performing Request Token Request: %@", self.oauthRequestTokenURL);
		
        NSMutableArray *params = [NSMutableArray array];
        
		// Append the oauth_callbackUrl parameter for requesting the request token
		MPURLRequestParameter *callbackParameter = nil;
		if (self.delegate && [self.delegate respondsToSelector: @selector(callbackURLForCompletedUserAuthorization)]) {
			NSURL *callbackURL = [self.delegate callbackURLForCompletedUserAuthorization];
			callbackParameter = [[[MPURLRequestParameter alloc] initWithName:@"oauth_callback" andValue:[callbackURL absoluteString]] autorelease];
            [params addObject:callbackParameter];
		} else {
			// oob = "Out of bounds"
			callbackParameter = [[[MPURLRequestParameter alloc] initWithName:@"oauth_callback" andValue:@"oob"] autorelease];
            [params addObject:callbackParameter];
		}
        
        if ([delegate_ respondsToSelector:@selector(additionalParametersForRequestTokenRequest)]) {
            [params addObjectsFromArray:[delegate_ additionalParametersForRequestTokenRequest]];
        }
		
		[self.oauthAPI performMethod:nil atURL:self.oauthRequestTokenURL withParameters:params withTarget:self andAction:@selector(_authenticationRequestForRequestTokenSuccessfulLoad:withData:)];
	}
}

- (void)_authenticationRequestForRequestTokenSuccessfulLoad:(MPOAuthAPIRequestLoader *)inLoader withData:(NSData *)inData {
	NSDictionary *oauthResponseParameters = inLoader.oauthResponse.oauthParameters;
	NSString *xoauthRequestAuthURL = [oauthResponseParameters objectForKey:@"xoauth_request_auth_url"]; // a common custom extension, used by Yahoo!
	NSURL *userAuthURL = xoauthRequestAuthURL ? [NSURL URLWithString:xoauthRequestAuthURL] : self.oauthAuthorizeTokenURL;
	NSURL *callbackURL = nil;
	
	if (!self.oauth10aModeActive) {
		callbackURL = [self.delegate respondsToSelector:@selector(callbackURLForCompletedUserAuthorization)] ? [self.delegate callbackURLForCompletedUserAuthorization] : nil;
	}
	
	NSDictionary *parameters = [NSDictionary dictionaryWithObjectsAndKeys:	[oauthResponseParameters objectForKey:	@"oauth_token"], @"oauth_token",
																													callbackURL, @"oauth_callback",
																													nil];
																						
	userAuthURL = [userAuthURL urlByAddingParameterDictionary:parameters];
	BOOL delegateWantsToBeInvolved = [self.delegate respondsToSelector:@selector(automaticallyRequestAuthenticationFromURL:withCallbackURL:)];
	
	if (!delegateWantsToBeInvolved || (delegateWantsToBeInvolved && [self.delegate automaticallyRequestAuthenticationFromURL:userAuthURL withCallbackURL:callbackURL])) {
		MPLog(@"--> Automatically Performing User Auth Request: %@", userAuthURL);
		[self _authenticationRequestForUserPermissionsConfirmationAtURL:userAuthURL];
	}
}

- (void)loader:(MPOAuthAPIRequestLoader *)inLoader didFailWithError:(NSError *)error {
	if ([self.delegate respondsToSelector:@selector(authenticationDidFailWithError:)]) {
		[self.delegate authenticationDidFailWithError: error];
	}
}

- (void)_authenticationRequestForUserPermissionsConfirmationAtURL:(NSURL *)userAuthURL {
#if TARGET_OS_IPHONE
	[[UIApplication sharedApplication] openURL:userAuthURL];
#else
    if ([self.delegate respondsToSelector:@selector(openOAuthURL:)]) {
        [self.delegate openOAuthURL:userAuthURL];
    } else {
        [[NSWorkspace sharedWorkspace] openURL:userAuthURL];
    }
#endif
}

- (void)_authenticationRequestForAccessToken {
	NSArray *params = nil;
	
	if (self.delegate && [self.delegate respondsToSelector: @selector(oauthVerifierForCompletedUserAuthorization)]) {
		MPURLRequestParameter *verifierParameter = nil;

		NSString *verifier = [self.delegate oauthVerifierForCompletedUserAuthorization];
		if (verifier) {
			verifierParameter = [[[MPURLRequestParameter alloc] initWithName:@"oauth_verifier" andValue:verifier] autorelease];
			params = [NSArray arrayWithObject:verifierParameter];
		}
	}
	
	if (self.oauthGetAccessTokenURL) {
		MPLog(@"--> Performing Access Token Request: %@", self.oauthGetAccessTokenURL);
		[self.oauthAPI performMethod:nil atURL:self.oauthGetAccessTokenURL withParameters:params withTarget:self andAction:nil];
	}
}

- (void)refreshAccessToken {
	MPURLRequestParameter *sessionHandleParameter = nil;
    MPURLRequestParameter *verifierParameter = nil;
	MPOAuthCredentialConcreteStore *credentials = (MPOAuthCredentialConcreteStore *)[self.oauthAPI credentials];
	
	if (credentials.sessionHandle) {
		sessionHandleParameter = [[MPURLRequestParameter alloc] init];
		sessionHandleParameter.name = @"oauth_session_handle";
		sessionHandleParameter.value = credentials.sessionHandle;
	}
    
    if (self.delegate && [self.delegate respondsToSelector: @selector(oauthVerifierForCompletedUserAuthorization)]) {
		NSString *verifier = [self.delegate oauthVerifierForCompletedUserAuthorization];
		if (verifier) {
			verifierParameter = [[[MPURLRequestParameter alloc] initWithName:@"oauth_verifier" andValue:verifier] autorelease];
		}
	}
    
    NSArray *parameters = nil;
    if (sessionHandleParameter || verifierParameter) {
        NSMutableArray *tempArray = [NSMutableArray array];
        if (sessionHandleParameter) {
            [tempArray addObject:sessionHandleParameter];
        }
        if (verifierParameter) {
            [tempArray addObject:verifierParameter];
        }
        parameters = tempArray;
    }
	
	[self.oauthAPI performMethod:nil
						   atURL:self.oauthGetAccessTokenURL
				  withParameters:parameters
					  withTarget:self       // cb: changed to self to react on errors
					   andAction:nil];
	
	[sessionHandleParameter release];	
}

#pragma mark -

//- (void)_requestTokenReceived:(NSNotification *)inNotification {
- (void) requestLoader:(MPOAuthAPIRequestLoader*)loader requestTokenReceivedWithParameters:(NSDictionary*)parameters;
{
	if ([parameters objectForKey:@"oauth_callback_confirmed"]) {
		self.oauth10aModeActive = YES;
	}
	
	[self.oauthAPI setCredential:[parameters objectForKey:@"oauth_token"] withName:kMPOAuthCredentialRequestToken];
	[self.oauthAPI setCredential:[parameters objectForKey:@"oauth_token_secret"] withName:kMPOAuthCredentialRequestTokenSecret];
    
    if ([delegate_ respondsToSelector:@selector(requestLoader:requestTokenReceivedWithParameters:)]) {
        [delegate_ requestLoader:loader requestTokenReceivedWithParameters:parameters];
    }
}

//- (void)_requestTokenRejected:(NSNotification *)inNotification {
- (void) requestLoader:(MPOAuthAPIRequestLoader*)loader requestTokenRejectedWithParameters:(NSDictionary*)parameters;
{
	[self.oauthAPI removeCredentialNamed:MPOAuthCredentialRequestTokenKey];
	[self.oauthAPI removeCredentialNamed:MPOAuthCredentialRequestTokenSecretKey];
    
    if ([delegate_ respondsToSelector:@selector(requestLoader:requestTokenRejectedWithParameters:)]) {
        [delegate_ requestLoader:loader requestTokenRejectedWithParameters:parameters];
    }
}

//- (void)_accessTokenReceived:(NSNotification *)inNotification {
- (void) requestLoader:(MPOAuthAPIRequestLoader*)loader accessTokenReceivedWithParameters:(NSDictionary*)parameters;
{
	[self.oauthAPI removeCredentialNamed:MPOAuthCredentialRequestTokenKey];
	[self.oauthAPI removeCredentialNamed:MPOAuthCredentialRequestTokenSecretKey];
	
	[self.oauthAPI setCredential:[parameters objectForKey:@"oauth_token"] withName:kMPOAuthCredentialAccessToken];
	[self.oauthAPI setCredential:[parameters objectForKey:@"oauth_token_secret"] withName:kMPOAuthCredentialAccessTokenSecret];
	
	if ([parameters objectForKey:MPOAuthCredentialSessionHandleKey]) {
		[self.oauthAPI setCredential:[parameters objectForKey:MPOAuthCredentialSessionHandleKey] withName:kMPOAuthCredentialSessionHandle];
	}

	[self.oauthAPI setAuthenticationState:MPOAuthAuthenticationStateAuthenticated];
	
	if ([parameters objectForKey:@"oauth_expires_in"]) {
		NSTimeInterval tokenRefreshInterval = (NSTimeInterval)[[parameters objectForKey:@"oauth_expires_in"] intValue];
		NSDate *tokenExpiryDate = [NSDate dateWithTimeIntervalSinceNow:tokenRefreshInterval];
		[[NSUserDefaults standardUserDefaults] setDouble:[tokenExpiryDate timeIntervalSinceReferenceDate] forKey:MPOAuthTokenRefreshDateDefaultsKey];
	
		if (tokenRefreshInterval > 0.0) {
			[self setTokenRefreshInterval:tokenRefreshInterval];
		}
	} else {
		[[NSUserDefaults standardUserDefaults] removeObjectForKey:MPOAuthTokenRefreshDateDefaultsKey];
	}
    
    if ([delegate_ respondsToSelector:@selector(requestLoader:accessTokenReceivedWithParameters:)]) {
        [delegate_ requestLoader:loader accessTokenReceivedWithParameters:parameters];
    }
}

- (void) requestLoader:(MPOAuthAPIRequestLoader*)loader accessTokenRejectedWithParameters:(NSDictionary*)parameters;
{
    if ([delegate_ respondsToSelector:@selector(requestLoader:accessTokenRejectedWithParameters:)]) {
        [delegate_ requestLoader:loader accessTokenRejectedWithParameters:parameters];
    }
}

- (void) requestLoader:(MPOAuthAPIRequestLoader*)loader accessTokenRefreshedWithParameters:(NSDictionary*)parameters;
{
    [self.oauthAPI setAuthenticationState:MPOAuthAuthenticationStateAuthenticated];
    
    if ([delegate_ respondsToSelector:@selector(requestLoader:accessTokenRefreshedWithParameters:)]) {
        [delegate_ requestLoader:loader accessTokenRefreshedWithParameters:parameters];
    }
}

- (void) requestLoader:(MPOAuthAPIRequestLoader*)loader errorOccuredWithStatus:(int)status withParameters:(NSDictionary*)parameters;
{
    if ([delegate_ respondsToSelector:@selector(requestLoader:errorOccuredWithStatus:withParameters:)]) {
        [delegate_ requestLoader:loader errorOccuredWithStatus:status withParameters:parameters];
    }
}


#pragma mark -
#pragma mark - Private APIs -

- (void)_performedLoad:(MPOAuthAPIRequestLoader *)inLoader receivingData:(NSData *)inData {
	//	NSLog(@"loaded %@, and got %@", inLoader, inData);
}

@end
