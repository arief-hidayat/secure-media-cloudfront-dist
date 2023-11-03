#!/usr/bin/env node
import 'source-map-support/register';
import * as cdk from 'aws-cdk-lib';
import {SignedUrlProtectedStack} from "../lib/signed-url-protected-stack";
import {Duration} from "aws-cdk-lib";
import {JwtProtectedStack} from "../lib/jwt-protected-stack";
import * as cloudfront from "aws-cdk-lib/aws-cloudfront";
import {MediaCloudFront} from "../lib/shared-props";

const app = new cdk.App();

const US_EAST_1: cdk.Environment = { account: process.env.CDK_DEFAULT_ACCOUNT, region: 'us-east-1' }

const JWT_TOKEN = {
    ttl: '+5m',
    keys: {
        "20231016_33b8808eb52dab2915bc": "8577de1fc1e8c39581a2593fe491567938833f2a907239593561457fef0c2f7bc66a116c3b8273bb915fe6975c3a0c07ab75a3f61480ca26a1cd878604dece42"
    }
}

// openssl genrsa -out CF-priv-key.pem 2048; openssl rsa -pubout -in CF-priv-key.pem -out CF-pub-key.pem;
const SIGNED_URL  = {
    publicKey: `-----BEGIN PUBLIC KEY-----
.....
-----END PUBLIC KEY-----
`,
    privateKey: `-----BEGIN PRIVATE KEY-----
.....
-----END PRIVATE KEY-----`,
    ttl: Duration.minutes(5)
}

const VOD_FOUNDATION_SOLUTION_1: MediaCloudFront  = {
    manifestDistributionAttrs: {
        // from VOD Foundation solution
        distributionId: 'EXXXXXXXXXXO1',
        // aws cloudfront get-distribution --id $DIST_ID
        domainName: 'dxxxxxxx1.cloudfront.net'
    },
    s3Origin: {
        region: 'ap-southeast-1',
        bucketArn: 'arn:aws:s3:::vod-foundation-destination-xxxxx',
        originAccessIdentityId: 'E1xxxxxx1',
    },
    sampleMasterManifests: {
        "ch01" : "/55f59595-8f20-495c-95b4-874cae93e115/AppleHLS1/01-seagulls.m3u8"
    },
    addCorsResponse: true,
}

const VOD_MEDIA_PACKAGE_SOLUTION_1: MediaCloudFront  = {
    manifestDistributionAttrs: {
        // from VOD solution with media Package.
        distributionId: 'EXXXXXXXXXXO2',
        // aws cloudfront get-distribution --id $DIST_ID
        // aws cloudfront get-distribution --id $DIST_ID --output json | jq -r '.Distribution.DomainName'
        domainName: 'dxxxxxx2.cloudfront.net'
    },
    httpOrigin: {
        // aws cloudfront get-distribution --id $DIST_ID --output json | jq -r '.Distribution.DistributionConfig.Origins.Items[0].DomainName'
        domainName: 'dxxxxxxxx2.egress.mediapackage-vod.us-east-1.amazonaws.com',
        originProps: {
            protocolPolicy: cloudfront.OriginProtocolPolicy.HTTPS_ONLY,
            originSslProtocols: [cloudfront.OriginSslPolicy.TLS_V1_2],
            httpsPort: 443,
            originShieldEnabled: false,
            readTimeout: cdk.Duration.seconds(30),
            keepaliveTimeout: cdk.Duration.seconds(5),
            connectionTimeout: cdk.Duration.seconds(10),
            connectionAttempts: 3
        }
    },
    // look at dynamoDB vod-solution table. HLS only.
    sampleMasterManifests: {
        "hls01" : "/out/v1/4ef4b6403656411fb4aa0015977b84d4/5e8641a30c6b43eca94cc988bc932052/0e096f8a1c4f406eb691926a69ef97bf/index.m3u8",
        "dash01" : "/out/v1/4ef4b6403656411fb4aa0015977b84d4/df848cbdae39493ea5505b9589a53934/2afe854668054f7aa4162231a7b452d9/index.mpd",
    },
    addCorsResponse: true,
}


// s3 origin (from VOD Foundation solution) protected by JWT
new JwtProtectedStack(app, 'JwtProtectedS3Stack', {
    env: US_EAST_1,
    jwtToken: JWT_TOKEN,
    ...VOD_FOUNDATION_SOLUTION_1
});

// MediaPackage origin (from VOD solution) protected by JWT
new JwtProtectedStack(app, 'JwtProtectedMediaPackageStack', {
    env: US_EAST_1,
    jwtToken: JWT_TOKEN,
    ...VOD_MEDIA_PACKAGE_SOLUTION_1
});

// S3 origin protected by signed URL
new SignedUrlProtectedStack(app, 'SignedUrlProtectedS3Stack', {
    env: US_EAST_1,
    signedUrl: SIGNED_URL,
    ...VOD_FOUNDATION_SOLUTION_1
});

// MediaPackage origin protected by signed URL. Can only HLS. No DASH support yet.
new SignedUrlProtectedStack(app, 'SignedUrlProtectedMediaPackageStack', {
    env: US_EAST_1,
    signedUrl: SIGNED_URL,
    ...VOD_MEDIA_PACKAGE_SOLUTION_1
});