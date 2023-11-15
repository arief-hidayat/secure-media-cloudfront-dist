import * as cdk from 'aws-cdk-lib';
import {CfnOutput, Duration} from 'aws-cdk-lib';
import {Construct} from 'constructs';
import * as cf from 'aws-cdk-lib/aws-cloudfront';
import * as fs from "fs";
import * as iam from 'aws-cdk-lib/aws-iam';
import {EdgeAuthTokenConfig, MediaCloudFront, OneTimeAccessConfig} from "./shared-props";
import {ProtectedMediaStack} from "./shared-stack";

interface EdgeAuthProtectedStackProps extends cdk.StackProps, MediaCloudFront {
  tokenConfig: EdgeAuthTokenConfig
  oneTimeAccessConfig?: OneTimeAccessConfig
}

export class EdgeAuthProtectedStack extends ProtectedMediaStack {
  constructor(scope: Construct, id: string, props: EdgeAuthProtectedStackProps) {
    super(scope, id, props);
    const leRole = this.createLambdaEdgeBasicExecutionRole();
    const origin = this.createOrigin(props);
    const liveManifestCachePolicy = this.createLiveManifestCachePolicy(props.manifestCachePolicyProps);
    const cfBehaviours: Record<string, cf.BehaviorOptions> = {}

    const validateEdgeAuthTokenCff = this.createCloudFrontFunctionValidateToken(props)
    if(props.sampleMasterManifests) {
      const getMasterManifestEdgeAuthFunc = this.createFuncGetMasterManifestEdgeAuth(leRole, props);
      cfBehaviours["/api/v2/urls/*"] = {
        origin: origin,
        viewerProtocolPolicy: cf.ViewerProtocolPolicy.REDIRECT_TO_HTTPS,
        allowedMethods: cf.AllowedMethods.ALLOW_ALL,
        cachedMethods: cf.CachedMethods.CACHE_GET_HEAD,
        cachePolicy: cf.CachePolicy.CACHING_DISABLED,
        originRequestPolicy: cf.OriginRequestPolicy.ALL_VIEWER,
        edgeLambdas: [{eventType: cf.LambdaEdgeEventType.VIEWER_REQUEST, includeBody: false, functionVersion: getMasterManifestEdgeAuthFunc.currentVersion}],
        compress: true
      }
    }
    const updateHlsManifestWithEdgeAuthFunc = props.oneTimeAccessConfig ?
        this.createFuncUpdateHlsManifestWithEdgeAuthDynamo(this.createLambdaEdgeWithDdbAdmin(), props):
        this.createFuncUpdateHlsManifestWithEdgeAuth(leRole, props)
    cfBehaviours["*.m3u8"] = {
      origin: origin,
      viewerProtocolPolicy: cf.ViewerProtocolPolicy.REDIRECT_TO_HTTPS,
      allowedMethods: cf.AllowedMethods.ALLOW_GET_HEAD,
      cachedMethods: cf.CachedMethods.CACHE_GET_HEAD,
      cachePolicy: props.oneTimeAccessConfig ? cf.CachePolicy.CACHING_DISABLED: liveManifestCachePolicy,
      originRequestPolicy: cf.OriginRequestPolicy.ALL_VIEWER,
      responseHeadersPolicy: cf.ResponseHeadersPolicy.CORS_ALLOW_ALL_ORIGINS_WITH_PREFLIGHT,
      edgeLambdas: [{eventType: cf.LambdaEdgeEventType.ORIGIN_REQUEST, includeBody: false, functionVersion: updateHlsManifestWithEdgeAuthFunc.currentVersion}],
      compress: true
    }
    const edgeAuthProtectedDist = new cf.Distribution(this, 'edgeAuthProtectedDist', {
      defaultBehavior: {
        origin: origin,
        viewerProtocolPolicy: cf.ViewerProtocolPolicy.REDIRECT_TO_HTTPS,
        allowedMethods: cf.AllowedMethods.ALLOW_GET_HEAD,
        cachedMethods: cf.CachedMethods.CACHE_GET_HEAD,
        cachePolicy: cf.CachePolicy.CACHING_OPTIMIZED,
        responseHeadersPolicy: cf.ResponseHeadersPolicy.CORS_ALLOW_ALL_ORIGINS_WITH_PREFLIGHT,
        functionAssociations: [{
          function: validateEdgeAuthTokenCff,
          eventType: cf.FunctionEventType.VIEWER_REQUEST
        }],
        compress: true
      },
      defaultRootObject: "",
      httpVersion: cf.HttpVersion.HTTP1_1,
      additionalBehaviors: cfBehaviours,
    });

    new CfnOutput(this, 'edgeAuthProtectedCloudFrontDomainName', {value: edgeAuthProtectedDist.domainName});
    new CfnOutput(this, 'edgeAuthProtectedCloudFrontDistributionId', {value: edgeAuthProtectedDist.distributionId});
  }


  createCloudFrontFunctionValidateToken(props: EdgeAuthProtectedStackProps) {
    const validateTokenFuncCode = cf.FunctionCode.fromInline(
        fs.readFileSync('./lib/functions/cffEdgeAuth.js', 'utf-8')
            .replace(/'TOKEN_KEYS'/g, JSON.stringify(props.tokenConfig.tokenKeys))
            .replace(/"__token__"/g, `"${props.tokenConfig.tokenName}"`)
            .replace(/"ESCAPE_EARLY"/g, `${props.tokenConfig.escapeEarly}`)
            .replace(/KEY_ID/g, props.tokenConfig.defaultKey)
            .replace(/windowSeconds = 300/g, `windowSeconds = ${props.tokenConfig.tokenTtl.toSeconds()}`)
    )
    return new cf.Function(this, 'validateEdgeAuthTokenCff', {
      code: validateTokenFuncCode,
      comment: 'Validate Edge Auth function',
    });
  }
  createFuncGetMasterManifestEdgeAuth(leRole: iam.Role, props: EdgeAuthProtectedStackProps) {
    return this.createLambdaFromFile(leRole, 'getMasterManifestEdgeAuthFunc',
        fs.readFileSync('./lib/functions/getMasterManifestEdgeAuth.js', 'utf-8')
            .replace(/'MASTER_MANIFESTS'/g, JSON.stringify(props.sampleMasterManifests))
            .replace(/MANIFEST_DOMAIN_NAME/g, props.manifestDistributionAttrs.domainName)
            .replace(/VIEWER_DOMAIN_NAME/g, props.customViewerDomainName ? props.customViewerDomainName : "")
            .replace(/'TOKEN_KEYS'/g, JSON.stringify(props.tokenConfig.tokenKeys))
            .replace(/"__token__"/g, `"${props.tokenConfig.tokenName}"`)
            .replace(/: "36000"/g, `: "${props.tokenConfig.tokenTtl.toSeconds()}"`)
            .replace(/"ESCAPE_EARLY"/g, `${props.tokenConfig.escapeEarly}`)
            .replace(/KEY_ID/g, props.tokenConfig.defaultKey),
        Duration.seconds(2));
  }

  createFuncUpdateHlsManifestWithEdgeAuthDynamo(leRole: iam.Role, props: EdgeAuthProtectedStackProps) {
    return this.createLambdaFromFile(leRole, 'updateHlsManifestWithEdgeAuthFunc',
        fs.readFileSync('./lib/functions/updateHlsManifestWithEdgeAuthDynamo.js', 'utf-8')
            .replace(/MANIFEST_DOMAIN_NAME/g, props.manifestDistributionAttrs.domainName)
            .replace(/VIEWER_DOMAIN_NAME/g, props.customViewerDomainName ? props.customViewerDomainName : "")
            .replace(/CORS_RESPONSE/g, props.addCorsResponse ? '*' : '')
            .replace(/'TOKEN_KEYS'/g, JSON.stringify(props.tokenConfig.tokenKeys))
            .replace(/"__token__"/g, `"${props.tokenConfig.tokenName}"`)
            .replace(/windowSeconds = 300/g, `windowSeconds = ${props.tokenConfig.tokenTtl.toSeconds()}`)
            .replace(/"ESCAPE_EARLY"/g, `${props.tokenConfig.escapeEarly}`)
            .replace(/KEY_ID/g, props.tokenConfig.defaultKey)
            .replace(/DDB_TABLE/g, `${props.oneTimeAccessConfig?.ddbTableName}`)
    );
  }
  createFuncUpdateHlsManifestWithEdgeAuth(leRole: iam.Role, props: EdgeAuthProtectedStackProps) {
    return this.createLambdaFromFile(leRole, 'updateHlsManifestWithEdgeAuthFunc',
        fs.readFileSync('./lib/functions/updateHlsManifestWithEdgeAuth.js', 'utf-8')
            .replace(/MANIFEST_DOMAIN_NAME/g, props.manifestDistributionAttrs.domainName)
            .replace(/VIEWER_DOMAIN_NAME/g, props.customViewerDomainName ? props.customViewerDomainName : "")
            .replace(/CORS_RESPONSE/g, props.addCorsResponse ? '*' : '')
            .replace(/'TOKEN_KEYS'/g, JSON.stringify(props.tokenConfig.tokenKeys))
            .replace(/"__token__"/g, `"${props.tokenConfig.tokenName}"`)
            .replace(/windowSeconds = 300/g, `windowSeconds = ${props.tokenConfig.tokenTtl.toSeconds()}`)
            .replace(/"ESCAPE_EARLY"/g, `${props.tokenConfig.escapeEarly}`)
            .replace(/KEY_ID/g, props.tokenConfig.defaultKey)
    );
  }
}
