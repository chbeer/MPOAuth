//
//  MPOAuthAPIRequestLoaderTests.h
//  MPOAuthConnection
//
//  Created by Karl Adam on 08.12.18.
//  Copyright 2008 matrixPointer. All rights reserved.
//

#import <SenTestingKit/SenTestingKit.h>
#import "MPOAuthAPIRequestLoader.h"


@interface MPOAuthAPIRequestLoaderTests : SenTestCase <MPOAuthAPIRequestLoaderDelegate> {
    NSTask *server;
}

@end
