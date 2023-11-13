#!/usr/bin/env node
import 'source-map-support/register';
import * as cdk from 'aws-cdk-lib';
import {SignedUrlProtectedStack} from "../lib/signed-url-protected-stack";
import {Duration} from "aws-cdk-lib";
import {JwtProtectedStack} from "../lib/jwt-protected-stack";
import * as cloudfront from "aws-cdk-lib/aws-cloudfront";
import {MediaCloudFront} from "../lib/shared-props";
import {EdgeAuthProtectedStack} from "../lib/edge-auth-protected-stack";

const app = new cdk.App();

const US_EAST_1: cdk.Environment = { account: process.env.CDK_DEFAULT_ACCOUNT, region: 'us-east-1' }

const VOD_FOUNDATION_SOLUTION_1: MediaCloudFront  = {
    manifestDistributionAttrs: {
        // from VOD Foundation solution
        distributionId: 'XXX',
        // aws cloudfront get-distribution --id E13F2DYVXF3AC9
        domainName: 'xxx.cloudfront.net'
    },
    s3Origin: {
        region: 'ap-southeast-1',
        bucketArn: 'arn:aws:s3:::vod-foundation-destination-xxx',
        originAccessIdentityId: 'xxx',
    },
    sampleMasterManifests: {
        "ch01" : "/55f59595-8f20-495c-95b4-874cae93e115/AppleHLS1/01-seagulls.m3u8"
    },
    addCorsResponse: true,
}

const MP_HTTP_ORIGIN_PROPS = {
    protocolPolicy: cloudfront.OriginProtocolPolicy.HTTPS_ONLY,
    originSslProtocols: [cloudfront.OriginSslPolicy.TLS_V1_2],
    httpsPort: 443,
    originShieldEnabled: false,
    readTimeout: cdk.Duration.seconds(30),
    keepaliveTimeout: cdk.Duration.seconds(5),
    connectionTimeout: cdk.Duration.seconds(10),
    connectionAttempts: 3
}

const VOD_MEDIA_PACKAGE_SOLUTION_1: MediaCloudFront  = {
    manifestDistributionAttrs: {
        // from VOD solution with media Package.
        distributionId: 'zzz',
        // aws cloudfront get-distribution --id $DIST_ID
        // aws cloudfront get-distribution --id $DIST_ID --output json | jq -r '.Distribution.DomainName'
        domainName: 'zzz.cloudfront.net'
    },
    httpOrigin: {
        // aws cloudfront get-distribution --id $DIST_ID --output json | jq -r '.Distribution.DistributionConfig.Origins.Items[0].DomainName'
        domainName: 'zzz.egress.mediapackage-vod.us-east-1.amazonaws.com',
        originProps: MP_HTTP_ORIGIN_PROPS
    },
    // look at dynamoDB vod-solution table. HLS only.
    sampleMasterManifests: {
        "hls01" : "/out/v1/3b403951e8f94387a101579973380259/5e8641a30c6b43eca94cc988bc932052/0e096f8a1c4f406eb691926a69ef97bf/index.m3u8",
        "dash01" : "/out/v1/3b403951e8f94387a101579973380259/df848cbdae39493ea5505b9589a53934/2afe854668054f7aa4162231a7b452d9/index.mpd",
        "hls02" : "/out/v1/4ef4b6403656411fb4aa0015977b84d4/5e8641a30c6b43eca94cc988bc932052/0e096f8a1c4f406eb691926a69ef97bf/index.m3u8",
        "dash02" : "/out/v1/4ef4b6403656411fb4aa0015977b84d4/df848cbdae39493ea5505b9589a53934/2afe854668054f7aa4162231a7b452d9/index.mpd",
    },
    addCorsResponse: true,
}

const VOD_MEDIA_PACKAGE_SOLUTION_2: MediaCloudFront  = {
    manifestDistributionAttrs: {
        // from VOD solution with media Package.
        distributionId: 'yyy',
        // aws cloudfront get-distribution --id $DIST_ID
        // aws cloudfront get-distribution --id $DIST_ID --output json | jq -r '.Distribution.DomainName'
        domainName: 'yyy.cloudfront.net'
    },
    httpOrigin: {
        // aws cloudfront get-distribution --id $DIST_ID --output json | jq -r '.Distribution.DistributionConfig.Origins.Items[0].DomainName'
        domainName: 'yyy.egress.mediapackage-vod.ap-southeast-1.amazonaws.com',
        originProps: MP_HTTP_ORIGIN_PROPS
    },
    // look at dynamoDB vod-solution table. HLS only.
    sampleMasterManifests: {
        "hls01" : "/out/v1/bf78a9e3c02444cb86f973c8076e0274/8b5ff4db2f6e4431be63e7e6fe3b74c0/6c52509d4a9e48e9b5ef954b38af41e9/index.m3u8",
        "dash01" : "/out/v1/bf78a9e3c02444cb86f973c8076e0274/a41379047a93473a82736805d3847f84/6e014314d50d4a399a5f35b9b8fabb2e/index.mpd",
    },
    addCorsResponse: true,
}


const JWT_TOKEN = {
    ttl: '+5m',
    keys: {
        "20231016_33b8808eb52dab2915bc": "8577de1fc1e8c39581a2593fe491567938833f2a907239593561457fef0c2f7bc66a116c3b8273bb915fe6975c3a0c07ab75a3f61480ca26a1cd878604dece42"
    }
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

new JwtProtectedStack(app, 'JwtProtectedMediaPackageSgStack', {
    env: US_EAST_1,
    jwtToken: JWT_TOKEN,
    ...VOD_MEDIA_PACKAGE_SOLUTION_2
});


const SIGNED_URL  = {
    // openssl genrsa -out CF-priv-key.pem 2048; openssl rsa -pubout -in CF-priv-key.pem -out CF-pub-key.pem;
    publicKey: `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAuQc90P589xuwlpAopjw+
UW86Pc3JE5p3/xeLMn67FDE2QSr4q5PdROWhlFAcBlwvTwlrnekFabrLk/AzTxNK
U+Yih/19MkNulF0u8vE56B91OO1jnmJt2jFYgv0mND0vpXoTy7Tg8Z44EtMByuQT
1Ud/2TGiXcIv+J/piDPogvIyrLz60LhgMKvAv7OG9CiB07Atf64I4kYtxVFMX3ZN
Sh2CGOmUH7M6iT3LZ9DwS02TW+TvaMLIyR0P20CHAbuiJEuZVB4aMyLgNVJGbU2T
u0aSb+St3zOAcqf0rZ+V88V1/RLJmSYt+CpYUYqLgHEdPP/xryY+srS1S8Z9EaZ4
VwIDAQAB
-----END PUBLIC KEY-----
`,
    privateKey: `-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC5Bz3Q/nz3G7CW
kCimPD5Rbzo9zckTmnf/F4syfrsUMTZBKvirk91E5aGUUBwGXC9PCWud6QVpusuT
8DNPE0pT5iKH/X0yQ26UXS7y8TnoH3U47WOeYm3aMViC/SY0PS+lehPLtODxnjgS
0wHK5BPVR3/ZMaJdwi/4n+mIM+iC8jKsvPrQuGAwq8C/s4b0KIHTsC1/rgjiRi3F
UUxfdk1KHYIY6ZQfszqJPctn0PBLTZNb5O9owsjJHQ/bQIcBu6IkS5lUHhozIuA1
UkZtTZO7RpJv5K3fM4Byp/Stn5XzxXX9EsmZJi34KlhRiouAcR08//GvJj6ytLVL
xn0RpnhXAgMBAAECggEAJGz+iHRxWZyD6UA8IG3fvtxs1Nn8afWRBhE2gBxe7By8
F5xEFFMpznR+mNokikP/tEmgfBfxztzNUzSIhVrA2T+HMMqAqTKJRIALzBwdUEtR
IoHpiLbL9ZadXDxGFyasiKE94G6dkjOZymrsAWthVC2dR77zvg2KsCGbMgs2DQEX
Ao7c/iu5gaHoY0ri8QUjvtBc0zmpGsKMT5x3bo7iONL6b7Bo6Jbfz5IvKM07ntHE
MBT+Tp6jYFciw2H5UTdISlF9i9if1LWLXao1MAqo7URhkVR+BYhV2Lt6jDXYEgoW
9paEo6/tmdlDKzfgAU08HQfUAv8Gu2eDeqOiE1Mt8QKBgQD3FYFaYypKsz4C9xze
XWRQa02tq738yMjvuJZG5q8dea98AAMgiOeL/b7GCqklwHofo61Nw1YLxIEKAGmX
m3uagGgUo/ShWwaKH61A0xrFX35PIsFjMaWYH6ADRTTqiIXaucCfNUspFzdAJg7d
gRCNrtWFlxoJsXOucKbKyGLEawKBgQC/tHt8nNgFbkf2RPjKuAUPjvSK8pBc93y0
itSEcISAp+OKyVttaxGEbnzIv0kd/whASt12UbaCtABmoh3qYCqmbEGmoYPq8sA6
j0ipLIP62HFWwIl9gyo79N/0v1slzlXttl/fL2wJpSsv5CaSynRBaahlxJJ2b1T4
XkvZrFR2xQKBgQCJwOmfNQ5NG2WFTbRAnRziYRCrtMZ1epPcYrMV0GLtMfyOS4ty
xiEhwVRtIWBwdcEghqaGZlNAuEuhAd3c8oiU+OYOK+KlWxRoSYTUUV3pkHXhNOVQ
oktKZsdVS25XG8pUyZ8EpDfFLvZUw2MiR2StOT49/qI7qT1vkcrL37CBBQKBgAui
3uP/eTVLLl8KbLeRV+1L1hghBRY/h3hF/QRU+BX/GtavxjbsCtIpCrX8tml1s4CD
itHFv/hLCMMyD/LMB4q2g32jzCgUuApV7CkopJIzVR3Y7f+KWKPvBzEJ9HRlA947
9bHMZRhoyChOBvFeDJRz317eAa3isBurTZtW1IGpAoGAeSS9hGFGS8VbJ46X3sAi
sK6ff5Vf9K09xxo3wYOgkKxy0T98OoW3Wbn9I6S+OCWD9SqechUGTLluHvOjN0Z6
dp/EKe+LdqNn2EgjL2QB2+IQk/6b8zpO8M9c8iFTMiC7O5qGpNZXf2EL0RR4a5Ms
60SqcRqppIHUWomFYw+SxTI=
-----END PRIVATE KEY-----`,
    ttl: Duration.minutes(5)
}

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
new SignedUrlProtectedStack(app, 'SignedUrlProtectedMediaPackage2Stack', {
    env: US_EAST_1,
    signedUrl: SIGNED_URL,
    ...VOD_MEDIA_PACKAGE_SOLUTION_2
});


const EDGE_AUTH_TOKEN = {
    defaultKey: 'ea01',
    tokenName: 'auth_token',
    tokenKeys: {
        // must be hexadecimal digit string with even-length
        'ea01': '1909CD2EE7EF0C27'
    },
    escapeEarly: false,
    tokenTtl: Duration.minutes(5)
}
// S3 origin protected by signed URL
new EdgeAuthProtectedStack(app, 'EdgeAuthProtectedS3Stack', {
    env: US_EAST_1,
    tokenConfig: EDGE_AUTH_TOKEN,
    ...VOD_FOUNDATION_SOLUTION_1
});

// MediaPackage origin protected by signed URL. Can only HLS. No DASH support yet.
new EdgeAuthProtectedStack(app, 'EdgeAuthProtectedMediaPackageStack', {
    env: US_EAST_1,
    tokenConfig: EDGE_AUTH_TOKEN,
    ...VOD_MEDIA_PACKAGE_SOLUTION_1
});

new EdgeAuthProtectedStack(app, 'EdgeAuthProtectedMediaPackageSgStack', {
    env: US_EAST_1,
    tokenConfig: EDGE_AUTH_TOKEN,
    oneTimeAccessConfig: {
        ddbTableName: 'OneTimeTokenGlobalDynamodbStack0'
    },
    ...VOD_MEDIA_PACKAGE_SOLUTION_2
});

new EdgeAuthProtectedStack(app, 'EdgeAuthProtectedMediaPackageSg2Stack', {
    env: US_EAST_1,
    tokenConfig: EDGE_AUTH_TOKEN,
    ...VOD_MEDIA_PACKAGE_SOLUTION_2
});