import * as cdk from 'aws-cdk-lib';
import {CfnOutput, Duration} from 'aws-cdk-lib';
import {Construct} from 'constructs';
import * as cf from 'aws-cdk-lib/aws-cloudfront';
import * as iam from 'aws-cdk-lib/aws-iam';
import * as lambda from 'aws-cdk-lib/aws-lambda';
import * as origins from 'aws-cdk-lib/aws-cloudfront-origins';
import * as s3 from 'aws-cdk-lib/aws-s3';
import * as fs from "fs";
import {MediaCloudFront, JwtTokenConfig} from "./shared-props";

interface JwtProtectedStackProps extends cdk.StackProps, MediaCloudFront {
    jwtToken: JwtTokenConfig
}

export class JwtProtectedStack extends cdk.Stack {
    constructor(scope: Construct, id: string, props: JwtProtectedStackProps) {
        super(scope, id, props);
        const lambdaEdgeBasicExecutionRole = new iam.Role(this, 'lambdaEdgeBasicExecutionRole', {
            assumedBy: new iam.CompositePrincipal(new iam.ServicePrincipal('edgelambda.amazonaws.com'), new iam.ServicePrincipal('lambda.amazonaws.com')),
            managedPolicies: [iam.ManagedPolicy.fromManagedPolicyArn(this, 'AWSLambdaBasicExecutionRole', 'arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole')],
        });
        let origin: cf.IOrigin
        if(props.s3Origin) {
            const s3Bucket = s3.Bucket.fromBucketAttributes(this, 'originS3', {
                bucketArn: props.s3Origin.bucketArn,
                region: props.s3Origin.region,
            })
            origin = new origins.S3Origin(s3Bucket, {
                originAccessIdentity: cf.OriginAccessIdentity.fromOriginAccessIdentityId(this, 'oai', props.s3Origin.originAccessIdentityId),
                originPath: props.s3Origin.originPath
            })
        } else if(props.httpOrigin) {
            origin = new origins.HttpOrigin(props.httpOrigin.domainName, props.httpOrigin.originProps)
        } else {
            throw new Error("no origin")
        }

        const liveManifestCachePolicy = new cf.CachePolicy(this, 'manifestCachePolicy', {
            minTtl: Duration.seconds(5),
            maxTtl: Duration.minutes(3),
            defaultTtl: Duration.seconds(6),
            headerBehavior: cf.CacheHeaderBehavior.allowList('Origin'),
            enableAcceptEncodingGzip: true,
            enableAcceptEncodingBrotli: true,
        })

        const validateTokenFuncCode = cf.FunctionCode.fromInline(
            fs.readFileSync('./lib/functions/cff.js', 'utf-8')
                .replace(/'JWT_KEYS'/g, JSON.stringify(props.jwtToken.keys))
        )
        const validateJwtTokenCff = new cf.Function(this, 'validateTokenFunc', {
            code: validateTokenFuncCode,
            comment: 'Validate JWT function',
        });
        const cfBehaviours: Record<string, cf.BehaviorOptions> = {}
        if (props.sampleMasterManifests) {
            const getMasterManifestJwtUrlCode = lambda.Code.fromInline(
                fs.readFileSync('./lib/functions/getMasterManifestJwtUrl.js', 'utf-8')
                    .replace(/'MASTER_MANIFESTS'/g, JSON.stringify(props.sampleMasterManifests))
                    .replace(/MANIFEST_DOMAIN_NAME/g, props.manifestDistributionAttrs.domainName)
                    .replace(/VIEWER_DOMAIN_NAME/g, props.customViewerDomainName ? props.customViewerDomainName : "")
                    .replace(/'JWT_KEYS'/g, JSON.stringify(props.jwtToken.keys))
                    .replace(/TOKEN_TTL/g, props.jwtToken.ttl ? props.jwtToken.ttl : '+5m')
            )
            const getMasterManifestJwtUrlFunc = new lambda.Function(this, 'getMasterManifestJwtUrl', {
                runtime: lambda.Runtime.NODEJS_16_X,
                handler: 'index.handler',
                role: lambdaEdgeBasicExecutionRole,
                code: getMasterManifestJwtUrlCode,
                timeout: Duration.seconds(5),
            });
            cfBehaviours["/api/v2/urls/*"] = {
                origin: origin,
                viewerProtocolPolicy: cf.ViewerProtocolPolicy.REDIRECT_TO_HTTPS,
                allowedMethods: cf.AllowedMethods.ALLOW_ALL,
                cachedMethods: cf.CachedMethods.CACHE_GET_HEAD,
                cachePolicy: liveManifestCachePolicy,
                originRequestPolicy: cf.OriginRequestPolicy.ALL_VIEWER,
                edgeLambdas: [{eventType: cf.LambdaEdgeEventType.ORIGIN_REQUEST, includeBody: false, functionVersion: getMasterManifestJwtUrlFunc.currentVersion}],
                compress: true
            }
        }

        const updateManifestWithJwtCode = lambda.Code.fromInline(
            fs.readFileSync('./lib/functions/updateManifestWithJwt.js', 'utf-8')
                .replace(/MANIFEST_DOMAIN_NAME/g, props.manifestDistributionAttrs.domainName)
                .replace(/VIEWER_DOMAIN_NAME/g, props.customViewerDomainName ? props.customViewerDomainName : "")
                .replace(/'JWT_KEYS'/g, JSON.stringify(props.jwtToken.keys))
                .replace(/TOKEN_TTL/g, props.jwtToken.ttl ? props.jwtToken.ttl : '+5m')
                .replace(/CORS_RESPONSE/g, props.addCorsResponse ? '*' : '')
        )
        const updateManifestWithJwtFunc = new lambda.Function(this, 'updateManifestWithJwt', {
            runtime: lambda.Runtime.NODEJS_16_X,
            handler: 'index.handler',
            role: lambdaEdgeBasicExecutionRole,
            code: updateManifestWithJwtCode,
            timeout: Duration.seconds(5),
        });
        cfBehaviours["*.mpd"] = {
            origin: origin,
            viewerProtocolPolicy: cf.ViewerProtocolPolicy.REDIRECT_TO_HTTPS,
            allowedMethods: cf.AllowedMethods.ALLOW_GET_HEAD,
            cachedMethods: cf.CachedMethods.CACHE_GET_HEAD,
            cachePolicy: liveManifestCachePolicy,
            originRequestPolicy: cf.OriginRequestPolicy.ALL_VIEWER,
            responseHeadersPolicy: cf.ResponseHeadersPolicy.CORS_ALLOW_ALL_ORIGINS_WITH_PREFLIGHT,
            edgeLambdas: [{
                eventType: cf.LambdaEdgeEventType.ORIGIN_REQUEST,
                includeBody: false,
                functionVersion: updateManifestWithJwtFunc.currentVersion
            }],
            compress: true
        }
        cfBehaviours["*.m3u8"] = {
            origin: origin,
            viewerProtocolPolicy: cf.ViewerProtocolPolicy.REDIRECT_TO_HTTPS,
            allowedMethods: cf.AllowedMethods.ALLOW_GET_HEAD,
            cachedMethods: cf.CachedMethods.CACHE_GET_HEAD,
            cachePolicy: liveManifestCachePolicy,
            originRequestPolicy: cf.OriginRequestPolicy.ALL_VIEWER,
            responseHeadersPolicy: cf.ResponseHeadersPolicy.CORS_ALLOW_ALL_ORIGINS_WITH_PREFLIGHT,
            edgeLambdas: [{
                eventType: cf.LambdaEdgeEventType.ORIGIN_REQUEST,
                includeBody: false,
                functionVersion: updateManifestWithJwtFunc.currentVersion
            }],
            compress: true
        }
        const viewerDistribution = new cf.Distribution(this, 'secureVodFoundation', {
            defaultBehavior: {
                origin: origin,
                viewerProtocolPolicy: cf.ViewerProtocolPolicy.REDIRECT_TO_HTTPS,
                allowedMethods: cf.AllowedMethods.ALLOW_GET_HEAD,
                cachedMethods: cf.CachedMethods.CACHE_GET_HEAD,
                cachePolicy: cf.CachePolicy.CACHING_OPTIMIZED,
                responseHeadersPolicy: cf.ResponseHeadersPolicy.CORS_ALLOW_ALL_ORIGINS_WITH_PREFLIGHT,
                originRequestPolicy: cf.OriginRequestPolicy.CORS_S3_ORIGIN,
                functionAssociations: [{
                    function: validateJwtTokenCff,
                    eventType: cf.FunctionEventType.VIEWER_REQUEST
                }],
                compress: true
            },
            defaultRootObject: "",
            httpVersion: cf.HttpVersion.HTTP1_1,
            additionalBehaviors: cfBehaviours,
        });
        new CfnOutput(this, 'jwtProtectedCloudFrontDomainName', {value: viewerDistribution.domainName});
        new CfnOutput(this, 'jwtProtectedCloudFrontDistributionId', {value: viewerDistribution.distributionId});
    }
}
