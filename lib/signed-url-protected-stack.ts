import * as cdk from 'aws-cdk-lib';
import {CfnOutput, Duration} from 'aws-cdk-lib';
import {Construct} from 'constructs';
import * as cf from 'aws-cdk-lib/aws-cloudfront';
import * as iam from 'aws-cdk-lib/aws-iam';
import * as fs from "fs";
import {MediaCloudFront, SignedUrl} from "./shared-props";
import {ProtectedMediaStack} from "./shared-stack";

interface SignedUrlProtectedStackProps extends cdk.StackProps, MediaCloudFront {
  signedUrl: SignedUrl
  jwtTokenKeys?: Record<string, string>
}


export class SignedUrlProtectedStack extends ProtectedMediaStack {
  constructor(scope: Construct, id: string, props: SignedUrlProtectedStackProps) {
    super(scope, id, props);
    const leRole = this.createLambdaEdgeBasicExecutionRole();
    const origin = this.createOrigin(props);
    const liveManifestCachePolicy = this.createLiveManifestCachePolicy(props.manifestCachePolicyProps);
    const cfBehaviours: Record<string, cf.BehaviorOptions> = {}
    if(props.jwtTokenKeys) {
      if(props.sampleMasterManifests) {
        const getMasterManifestJwtUrlFunc = this.createFuncGetMasterManifestJwtUrl(leRole, props)
        cfBehaviours["/api/v2/urls/*"] = {
          origin: origin,
          viewerProtocolPolicy: cf.ViewerProtocolPolicy.REDIRECT_TO_HTTPS,
          allowedMethods: cf.AllowedMethods.ALLOW_ALL,
          cachedMethods: cf.CachedMethods.CACHE_GET_HEAD,
          cachePolicy: cf.CachePolicy.CACHING_DISABLED,
          originRequestPolicy: cf.OriginRequestPolicy.ALL_VIEWER,
          edgeLambdas: [{eventType: cf.LambdaEdgeEventType.VIEWER_REQUEST, includeBody: false, functionVersion: getMasterManifestJwtUrlFunc.currentVersion}],
          compress: true
        }
      }
    }

    const pubKey = new cf.PublicKey(this, 'cfPubKey', {
      encodedKey: props.signedUrl.publicKey,
    });
    const trustedKeyGroup = new cf.KeyGroup(this, 'cfKeyGroup', { items: [pubKey] });

    const updateHlsManifestWithSignedUrlFunc = this.createFuncUpdateHlsManifestWithSignedUrl(leRole, pubKey, props)
    if(props.sampleMasterManifests) {
      const getMasterManifestSignedUrlFunc = this.createFuncGetMasterManifestSignedUrl(leRole, pubKey, props)
      cfBehaviours["/api/v1/urls/*"] = {
        origin: origin,
        viewerProtocolPolicy: cf.ViewerProtocolPolicy.REDIRECT_TO_HTTPS,
        allowedMethods: cf.AllowedMethods.ALLOW_ALL,
        cachedMethods: cf.CachedMethods.CACHE_GET_HEAD,
        cachePolicy: cf.CachePolicy.CACHING_DISABLED,
        originRequestPolicy: cf.OriginRequestPolicy.ALL_VIEWER,
        edgeLambdas: [{eventType: cf.LambdaEdgeEventType.VIEWER_REQUEST, includeBody: false, functionVersion: getMasterManifestSignedUrlFunc.currentVersion}],
        compress: true
      }
    }
    cfBehaviours["*.m3u8"] = {
      origin: origin,
      viewerProtocolPolicy: cf.ViewerProtocolPolicy.REDIRECT_TO_HTTPS,
      allowedMethods: cf.AllowedMethods.ALLOW_GET_HEAD,
      cachedMethods: cf.CachedMethods.CACHE_GET_HEAD,
      cachePolicy: liveManifestCachePolicy,
      originRequestPolicy: cf.OriginRequestPolicy.ALL_VIEWER,
      responseHeadersPolicy: cf.ResponseHeadersPolicy.CORS_ALLOW_ALL_ORIGINS_WITH_PREFLIGHT,
      edgeLambdas: [{eventType: cf.LambdaEdgeEventType.ORIGIN_REQUEST, includeBody: false, functionVersion: updateHlsManifestWithSignedUrlFunc.currentVersion}],
      trustedKeyGroups: [trustedKeyGroup],
      compress: true
    }
    const signedUrlProtectedDist = new cf.Distribution(this, 'signedUrlProtectedDist', {
      defaultBehavior: {
        origin: origin,
        viewerProtocolPolicy: cf.ViewerProtocolPolicy.REDIRECT_TO_HTTPS,
        allowedMethods: cf.AllowedMethods.ALLOW_GET_HEAD,
        cachedMethods: cf.CachedMethods.CACHE_GET_HEAD,
        cachePolicy: cf.CachePolicy.CACHING_OPTIMIZED,
        responseHeadersPolicy: cf.ResponseHeadersPolicy.CORS_ALLOW_ALL_ORIGINS_WITH_PREFLIGHT, // add-cors
        trustedKeyGroups: [trustedKeyGroup],
        compress: true
      },
      defaultRootObject: "",
      httpVersion: cf.HttpVersion.HTTP1_1,
      additionalBehaviors: cfBehaviours,
    });

    new CfnOutput(this, 'signedUrlProtectedCloudFrontDomainName', {value: signedUrlProtectedDist.domainName});
    new CfnOutput(this, 'signedUrlProtectedCloudFrontDistributionId', {value: signedUrlProtectedDist.distributionId});

    if(props.jwtTokenKeys) {
      const updateHlsTokenManifestWithSignedUrlFunc = this.createFuncUpdateHlsTokenManifestWithSignedUrl(leRole, pubKey, props)
      const jwtSignedUrlProtectedDist = new cf.Distribution(this, 'jwtSignedUrlProtectedDist', {
        defaultBehavior: {
          origin: origin,
          viewerProtocolPolicy: cf.ViewerProtocolPolicy.REDIRECT_TO_HTTPS,
          allowedMethods: cf.AllowedMethods.ALLOW_GET_HEAD,
          cachedMethods: cf.CachedMethods.CACHE_GET_HEAD,
          cachePolicy: cf.CachePolicy.CACHING_OPTIMIZED,
          responseHeadersPolicy: cf.ResponseHeadersPolicy.CORS_ALLOW_ALL_ORIGINS_WITH_PREFLIGHT, // add-cors
          trustedKeyGroups: [trustedKeyGroup],
          compress: true
        },
        defaultRootObject: "",
        httpVersion: cf.HttpVersion.HTTP1_1,
        additionalBehaviors: {
          "*.m3u8" : {
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
              functionVersion: updateHlsTokenManifestWithSignedUrlFunc.currentVersion
            }],
            compress: true
          }
        },
      });
      new CfnOutput(this, 'jwtSignedUrlProtectedCloudFrontDomainName', {value: jwtSignedUrlProtectedDist.domainName});
      new CfnOutput(this, 'jwtSignedUrlProtectedCloudFrontDistributionId', {value: jwtSignedUrlProtectedDist.distributionId});
    }
  }

  createFuncGetMasterManifestJwtUrl(leRole: iam.Role, props: SignedUrlProtectedStackProps) {
    return this.createLambdaFromFile(leRole, 'getMasterManifestJwtUrl',
        fs.readFileSync('./lib/functions/getMasterManifestJwtUrl.js', 'utf-8')
            .replace(/'MASTER_MANIFESTS'/g, JSON.stringify(props.sampleMasterManifests))
            .replace(/MANIFEST_DOMAIN_NAME/g, props.manifestDistributionAttrs.domainName)
            .replace(/VIEWER_DOMAIN_NAME/g, props.customViewerDomainName ? props.customViewerDomainName : "")
            .replace(/'JWT_KEYS'/g, JSON.stringify(props.jwtTokenKeys)),
        Duration.seconds(2)
    )
  }

  createFuncGetMasterManifestSignedUrl(leRole: iam.Role, pubKey: cf.PublicKey, props: SignedUrlProtectedStackProps) {
    return this.createLambdaFromFile(leRole, 'getMasterManifestSignedUrl',
        fs.readFileSync('./lib/functions/getMasterManifestSignedUrl.js', 'utf-8')
            .replace(/'MASTER_MANIFESTS'/g, JSON.stringify(props.sampleMasterManifests))
            .replace(/KEY_PAIR_ID/g, pubKey.publicKeyId)
            .replace(/PRIVATE_KEY/g, props.signedUrl.privateKey)
            .replace(/: 300/g, `: ${props.signedUrl.ttl.toSeconds()}`),
        Duration.seconds(2)
    )
  }
  createFuncUpdateHlsManifestWithSignedUrl(leRole: iam.Role, pubKey: cf.PublicKey, props: SignedUrlProtectedStackProps) {
    return this.createLambdaFromFile(leRole, 'updateHlsManifestWithSignedUrl',
        fs.readFileSync('./lib/functions/updateHlsManifestWithSignedUrl.js', 'utf-8')
            .replace(/MANIFEST_DOMAIN_NAME/g, props.manifestDistributionAttrs.domainName)
            .replace(/VIEWER_DOMAIN_NAME/g, props.customViewerDomainName ? props.customViewerDomainName : "")
            .replace(/CORS_RESPONSE/g, props.addCorsResponse ? '*' : '')
            .replace(/KEY_PAIR_ID/g, pubKey.publicKeyId)
            .replace(/PRIVATE_KEY/g, props.signedUrl.privateKey)
            .replace(/duration = 300/g, `duration = ${props.signedUrl.ttl.toSeconds()}`)
    )
  }
  createFuncUpdateHlsTokenManifestWithSignedUrl(leRole: iam.Role, pubKey: cf.PublicKey, props: SignedUrlProtectedStackProps) {
    return this.createLambdaFromFile(leRole, 'updateHlsTokenManifestWithSignedUrlFunc',
        fs.readFileSync('./lib/functions/updateHlsTokenManifestWithSignedUrl.js', 'utf-8')
            .replace(/MANIFEST_DOMAIN_NAME/g, props.manifestDistributionAttrs.domainName)
            .replace(/VIEWER_DOMAIN_NAME/g, props.customViewerDomainName ? props.customViewerDomainName : "")
            .replace(/'JWT_KEYS'/g, JSON.stringify(props.jwtTokenKeys))
            .replace(/CORS_RESPONSE/g, props.addCorsResponse ? '*' : '')
            .replace(/KEY_PAIR_ID/g, pubKey.publicKeyId)
            .replace(/duration = 300/g, `duration = ${props.signedUrl.ttl.toSeconds()}`)
            .replace(/PRIVATE_KEY/g, props.signedUrl.privateKey))
  }
}
