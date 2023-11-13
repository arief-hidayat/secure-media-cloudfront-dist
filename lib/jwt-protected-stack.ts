import * as cdk from 'aws-cdk-lib';
import {CfnOutput} from 'aws-cdk-lib';
import {Construct} from 'constructs';
import * as cf from 'aws-cdk-lib/aws-cloudfront';
import * as iam from 'aws-cdk-lib/aws-iam';
import * as fs from "fs";
import {MediaCloudFront, JwtTokenConfig} from "./shared-props";
import {ProtectedMediaStack} from "./shared-stack";

interface JwtProtectedStackProps extends cdk.StackProps, MediaCloudFront {
    jwtToken: JwtTokenConfig
}

export class JwtProtectedStack extends ProtectedMediaStack {
    constructor(scope: Construct, id: string, props: JwtProtectedStackProps) {
        super(scope, id, props);
        const leRole = this.createLambdaEdgeBasicExecutionRole();
        const origin = this.createOrigin(props);
        const liveManifestCachePolicy = this.createLiveManifestCachePolicy();
        const validateJwtTokenCff = this.createCloudFrontFunctionValidateJwtToken(props)
        const cfBehaviours: Record<string, cf.BehaviorOptions> = {}
        if (props.sampleMasterManifests) {
            const getMasterManifestJwtUrlFunc = this.createFuncGetMasterManifestJwtUrl(leRole, props)
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
        const updateManifestWithJwtFunc = this.createFuncUpdateManifestWithJwt(leRole, props)
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

    createCloudFrontFunctionValidateJwtToken(props: JwtProtectedStackProps) {
        const validateTokenFuncCode = cf.FunctionCode.fromInline(
            fs.readFileSync('./lib/functions/cff.js', 'utf-8')
                .replace(/'JWT_KEYS'/g, JSON.stringify(props.jwtToken.keys))
        )
        return new cf.Function(this, 'validateTokenFunc', {
            code: validateTokenFuncCode,
            comment: 'Validate JWT function',
        });
    }
    createFuncGetMasterManifestJwtUrl(leRole: iam.Role, props: JwtProtectedStackProps) {
        return this.createLambdaFromFile(leRole, 'getMasterManifestJwtUrl',
            fs.readFileSync('./lib/functions/getMasterManifestJwtUrl.js', 'utf-8')
                .replace(/'MASTER_MANIFESTS'/g, JSON.stringify(props.sampleMasterManifests))
                .replace(/MANIFEST_DOMAIN_NAME/g, props.manifestDistributionAttrs.domainName)
                .replace(/VIEWER_DOMAIN_NAME/g, props.customViewerDomainName ? props.customViewerDomainName : "")
                .replace(/'JWT_KEYS'/g, JSON.stringify(props.jwtToken.keys))
                .replace(/TOKEN_TTL/g, props.jwtToken.ttl ? props.jwtToken.ttl : '+5m')
        )
    }

    createFuncUpdateManifestWithJwt(leRole: iam.Role, props: JwtProtectedStackProps) {
        return this.createLambdaFromFile(leRole, 'updateManifestWithJwt',
            fs.readFileSync('./lib/functions/updateManifestWithJwt.js', 'utf-8')
                .replace(/MANIFEST_DOMAIN_NAME/g, props.manifestDistributionAttrs.domainName)
                .replace(/VIEWER_DOMAIN_NAME/g, props.customViewerDomainName ? props.customViewerDomainName : "")
                .replace(/'JWT_KEYS'/g, JSON.stringify(props.jwtToken.keys))
                .replace(/TOKEN_TTL/g, props.jwtToken.ttl ? props.jwtToken.ttl : '+5m')
                .replace(/CORS_RESPONSE/g, props.addCorsResponse ? '*' : ''))
    }
}
