import * as cdk from 'aws-cdk-lib';
import {CfnOutput, Duration} from 'aws-cdk-lib';
import {Construct} from 'constructs';
import * as cf from 'aws-cdk-lib/aws-cloudfront';
import * as iam from 'aws-cdk-lib/aws-iam';
import * as lambda from 'aws-cdk-lib/aws-lambda';
import * as origins from 'aws-cdk-lib/aws-cloudfront-origins';
import * as s3 from 'aws-cdk-lib/aws-s3';
import * as fs from "fs";
import {MediaCloudFront, SignedUrl} from "./shared-props";

interface SignedUrlProtectedStackProps extends cdk.StackProps, MediaCloudFront {
  signedUrl: SignedUrl
  jwtTokenKeys?: Record<string, string>
}


export class SignedUrlProtectedStack extends cdk.Stack {
  constructor(scope: Construct, id: string, props: SignedUrlProtectedStackProps) {
    super(scope, id, props);
    const lambdaEdgeBasicExecutionRole = new iam.Role(this, 'lambdaEdgeBasicExecutionRole', {
      assumedBy: new iam.CompositePrincipal(new iam.ServicePrincipal('edgelambda.amazonaws.com'), new iam.ServicePrincipal('lambda.amazonaws.com')) ,
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

    let edgeLambdas: cf.EdgeLambda[] = []
    if(props.addCorsResponse) {
      const addCorsFunc = new lambda.Function(this, 'addCors', {
        runtime: lambda.Runtime.NODEJS_18_X,
        handler: 'addCors.handler',
        role: lambdaEdgeBasicExecutionRole,
        code: lambda.Code.fromAsset('./lib/functions'),
        timeout: Duration.seconds(5),
      });
      edgeLambdas = [{
        eventType: cf.LambdaEdgeEventType.ORIGIN_RESPONSE,
        includeBody: false,
        functionVersion: addCorsFunc.currentVersion
      }]
    }
    const liveManifestCachePolicy = new cf.CachePolicy(this, 'liveManifestCachePolicy', {
      minTtl: Duration.seconds(5),
      maxTtl: Duration.minutes(3),
      defaultTtl: Duration.seconds(6),
      headerBehavior: cf.CacheHeaderBehavior.allowList('Origin'),
      enableAcceptEncodingGzip: true,
      enableAcceptEncodingBrotli: true,
    })

    const cfBehaviours: Record<string, cf.BehaviorOptions> = {}
    if(props.jwtTokenKeys) {
      //TODO: deploy cloudfront function for JWT token validation.
      const validateTokenFuncCode = cf.FunctionCode.fromInline(
          fs.readFileSync('./lib/functions/cff.js', 'utf-8')
          .replace(/'JWT_KEYS'/g, JSON.stringify(props.jwtTokenKeys))
      )
      const validateJwtTokenCff = new cf.Function(this, 'validateTokenFunc', {
        code: validateTokenFuncCode,
        comment: 'Validate JWT function',
        functionName: 'validateTokenFunc'
      });
      if(props.sampleMasterManifests) {
        const getMasterManifestJwtUrlCode = lambda.Code.fromInline(
            fs.readFileSync('./lib/functions/getMasterManifestJwtUrl.js', 'utf-8')
                .replace(/'MASTER_MANIFESTS'/g, JSON.stringify(props.sampleMasterManifests))
                .replace(/MANIFEST_DOMAIN_NAME/g, props.manifestDistributionAttrs.domainName)
                .replace(/VIEWER_DOMAIN_NAME/g, props.customViewerDomainName ? props.customViewerDomainName : "")
                .replace(/'JWT_KEYS'/g, JSON.stringify(props.jwtTokenKeys))
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
    }


    const pubKey = new cf.PublicKey(this, 'cfPubKey', {
      encodedKey: props.signedUrl.publicKey,
    });
    const trustedKeyGroup = new cf.KeyGroup(this, 'cfKeyGroup', {
      items: [pubKey],
    });
    const updateHlsManifestWithSignedUrlCode = lambda.Code.fromInline(
        fs.readFileSync('./lib/functions/updateHlsManifestWithSignedUrl.js', 'utf-8')
            .replace(/MANIFEST_DOMAIN_NAME/g, props.manifestDistributionAttrs.domainName)
            .replace(/VIEWER_DOMAIN_NAME/g, props.customViewerDomainName ? props.customViewerDomainName : "")
            .replace(/CORS_RESPONSE/g, props.addCorsResponse ? '*' : '')
            .replace(/KEY_PAIR_ID/g, pubKey.publicKeyId)
            .replace(/PRIVATE_KEY/g, props.signedUrl.privateKey))
    // trustedKeyGroup.keyGroupId
    const updateHlsManifestWithSignedUrlFunc = new lambda.Function(this, 'updateHlsManifestWithSignedUrl', {
      runtime: lambda.Runtime.NODEJS_16_X,
      handler: 'index.handler',
      role: lambdaEdgeBasicExecutionRole,
      code: updateHlsManifestWithSignedUrlCode,
      timeout: Duration.seconds(5),
    });

    if(props.sampleMasterManifests) {
      const getMasterManifestSignedUrlCode = lambda.Code.fromInline(
          fs.readFileSync('./lib/functions/getMasterManifestSignedUrl.js', 'utf-8')
              .replace(/'MASTER_MANIFESTS'/g, JSON.stringify(props.sampleMasterManifests))
              .replace(/KEY_PAIR_ID/g, pubKey.publicKeyId)
              .replace(/PRIVATE_KEY/g, props.signedUrl.privateKey))
      const getMasterManifestSignedUrlFunc = new lambda.Function(this, 'getMasterManifestSignedUrl', {
        runtime: lambda.Runtime.NODEJS_16_X,
        handler: 'index.handler',
        role: lambdaEdgeBasicExecutionRole,
        code: getMasterManifestSignedUrlCode,
        timeout: Duration.seconds(5),
      });
      cfBehaviours["/api/v1/urls/*"] = {
        origin: origin,
        viewerProtocolPolicy: cf.ViewerProtocolPolicy.REDIRECT_TO_HTTPS,
        allowedMethods: cf.AllowedMethods.ALLOW_ALL,
        cachedMethods: cf.CachedMethods.CACHE_GET_HEAD,
        cachePolicy: liveManifestCachePolicy,
        originRequestPolicy: cf.OriginRequestPolicy.ALL_VIEWER,
        edgeLambdas: [{eventType: cf.LambdaEdgeEventType.ORIGIN_REQUEST, includeBody: false, functionVersion: getMasterManifestSignedUrlFunc.currentVersion}],
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
        edgeLambdas: edgeLambdas,
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
      const updateHlsTokenManifestWithSignedUrlCode = lambda.Code.fromInline(
          fs.readFileSync('./lib/functions/updateHlsTokenManifestWithSignedUrl.js', 'utf-8')
              .replace(/MANIFEST_DOMAIN_NAME/g, props.manifestDistributionAttrs.domainName)
              .replace(/VIEWER_DOMAIN_NAME/g, props.customViewerDomainName ? props.customViewerDomainName : "")
              .replace(/'JWT_KEYS'/g, JSON.stringify(props.jwtTokenKeys))
              .replace(/CORS_RESPONSE/g, props.addCorsResponse ? '*' : '')
              .replace(/KEY_PAIR_ID/g, pubKey.publicKeyId)
              .replace(/PRIVATE_KEY/g, props.signedUrl.privateKey))
      const updateHlsTokenManifestWithSignedUrlFunc = new lambda.Function(this, 'updateHlsTokenManifestWithSignedUrlFunc', {
        runtime: lambda.Runtime.NODEJS_16_X,
        handler: 'index.handler',
        role: lambdaEdgeBasicExecutionRole,
        code: updateHlsTokenManifestWithSignedUrlCode,
        timeout: Duration.seconds(5),
      });
      const jwtSignedUrlProtectedDist = new cf.Distribution(this, 'jwtSignedUrlProtectedDist', {
        defaultBehavior: {
          origin: origin,
          viewerProtocolPolicy: cf.ViewerProtocolPolicy.REDIRECT_TO_HTTPS,
          allowedMethods: cf.AllowedMethods.ALLOW_GET_HEAD,
          cachedMethods: cf.CachedMethods.CACHE_GET_HEAD,
          cachePolicy: cf.CachePolicy.CACHING_OPTIMIZED,
          edgeLambdas: edgeLambdas,
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
}
