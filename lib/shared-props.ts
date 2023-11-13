import {Duration} from "aws-cdk-lib";
import {HttpOriginProps} from "aws-cdk-lib/aws-cloudfront-origins";
import * as cf from "aws-cdk-lib/aws-cloudfront";
import * as cdk from "aws-cdk-lib";

export interface SignedUrl {
    publicKey: string
    privateKey: string
    ttl: Duration
}
export interface S3OriginInfo {
    bucketArn: string,
    region: string,
    originAccessIdentityId: string,
    originPath?: string,
}
export interface HttpOriginInfo {
    domainName: string,
    originProps?: HttpOriginProps,
}
export interface JwtTokenConfig {
    keys: Record<string, string>
    ttl: string // +5m
}

export interface EdgeAuthTokenConfig {
    tokenName: string,
    tokenKeys?: Record<string, string>,
    tokenTtl: cdk.Duration,
    defaultKey: string,
    escapeEarly: boolean,
}

export interface OneTimeAccessConfig {
    ddbTableName: string,
}

export interface MediaCloudFront {
    manifestDistributionAttrs: cf.DistributionAttributes
    s3Origin?: S3OriginInfo
    httpOrigin?: HttpOriginInfo
    addCorsResponse: boolean
    customViewerDomainName?: string
    sampleMasterManifests?: Record<string, string>
}