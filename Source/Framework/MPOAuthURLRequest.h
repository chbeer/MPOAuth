//
//  MPOAuthURLRequest.h
//  MPOAuthConnection
//
//  Created by Karl Adam on 08.12.05.
//  Copyright 2008 matrixPointer. All rights reserved.
//

#import <Foundation/Foundation.h>


@interface MPOAuthURLRequest : NSObject {
@private
	NSURL			*_url;
	NSString		*_httpMethod;
	NSURLRequest	*_urlRequest;
	NSMutableArray	*_parameters;
    
    BOOL             _oAuthParameterInHeader;
}

@property (nonatomic, readwrite, retain) NSURL *url;
@property (nonatomic, readwrite, retain) NSString *HTTPMethod;
@property (nonatomic, readonly, retain) NSURLRequest *urlRequest;
@property (nonatomic, readwrite, retain) NSMutableArray *parameters;

@property (nonatomic, readwrite, assign) BOOL oAuthParameterInHeader;

- (id)initWithURL:(NSURL *)inURL andParameters:(NSArray *)parameters;
- (id)initWithURLRequest:(NSURLRequest *)inRequest;

- (void)addParameters:(NSArray *)inParameters;

- (NSURLRequest  *)urlRequestSignedWithSecret:(NSString *)inSecret usingMethod:(NSString *)inScheme;

@end
