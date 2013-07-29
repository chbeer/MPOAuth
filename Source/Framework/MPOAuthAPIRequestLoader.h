//
//  MPOAuthAPIRequestLoader.h
//  MPOAuthConnection
//
//  Created by Karl Adam on 08.12.05.
//  Copyright 2008 matrixPointer. All rights reserved.
//

#import <Foundation/Foundation.h>

@class MPOAuthAPIRequestLoader;

typedef void(^MPOAuthRequestLoaderHandler)(MPOAuthAPIRequestLoader *loader, NSData *data, NSError *error);

@protocol MPOAuthAPIRequestLoaderDelegate <NSObject>

@optional
- (void) requestLoader:(MPOAuthAPIRequestLoader*)loader requestTokenReceivedWithParameters:(NSDictionary*)parameters;
- (void) requestLoader:(MPOAuthAPIRequestLoader*)loader requestTokenRejectedWithParameters:(NSDictionary*)parameters;
- (void) requestLoader:(MPOAuthAPIRequestLoader*)loader accessTokenReceivedWithParameters:(NSDictionary*)parameters;
- (void) requestLoader:(MPOAuthAPIRequestLoader*)loader accessTokenRejectedWithParameters:(NSDictionary*)parameters;
- (void) requestLoader:(MPOAuthAPIRequestLoader*)loader accessTokenRefreshedWithParameters:(NSDictionary*)parameters;

- (void) requestLoader:(MPOAuthAPIRequestLoader*)loader errorOccuredWithStatus:(int)status withParameters:(NSDictionary*)parameters;

@end

@protocol MPOAuthCredentialStore;
@protocol MPOAuthParameterFactory;

@class MPOAuthURLRequest;
@class MPOAuthURLResponse;
@class MPOAuthCredentialConcreteStore;

@interface MPOAuthAPIRequestLoader : NSObject {
	MPOAuthCredentialConcreteStore	*_credentials;
	MPOAuthURLRequest				*_oauthRequest;
	MPOAuthURLResponse				*_oauthResponse;
	NSMutableData					*_dataBuffer;
	NSString						*_dataAsString;
	NSError							*_error;
    
	id<MPOAuthAPIRequestLoaderDelegate>     _delegate;
    MPOAuthRequestLoaderHandler             _handler;
    
}

@property (nonatomic, readwrite, retain) id <MPOAuthCredentialStore, MPOAuthParameterFactory> credentials;
@property (nonatomic, readwrite, retain) MPOAuthURLRequest *oauthRequest;
@property (nonatomic, readwrite, retain) MPOAuthURLResponse *oauthResponse;
@property (nonatomic, readonly, retain) NSData *data;
@property (nonatomic, readonly, retain) NSString *responseString;
@property (nonatomic, readwrite, assign) id delegate;
@property (nonatomic, readwrite, copy) MPOAuthRequestLoaderHandler handler;

- (id)initWithURL:(NSURL *)inURL;
- (id)initWithRequest:(MPOAuthURLRequest *)inRequest;

- (void)loadSynchronously:(BOOL)inSynchronous;

@end

