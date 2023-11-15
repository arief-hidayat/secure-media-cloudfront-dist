import * as cdk from 'aws-cdk-lib';
import {Duration} from 'aws-cdk-lib';
import * as cf from 'aws-cdk-lib/aws-cloudfront';
import * as iam from 'aws-cdk-lib/aws-iam';
import * as lambda from 'aws-cdk-lib/aws-lambda';
import * as origins from 'aws-cdk-lib/aws-cloudfront-origins';
import * as s3 from 'aws-cdk-lib/aws-s3';
import {MediaCloudFront, S3OriginInfo} from "./shared-props";

export class ProtectedMediaStack extends cdk.Stack {
    createLambdaEdgeBasicExecutionRole() {
        return new iam.Role(this, 'lambdaEdgeBasicExecutionRole', {
            assumedBy: new iam.CompositePrincipal(new iam.ServicePrincipal('edgelambda.amazonaws.com'), new iam.ServicePrincipal('lambda.amazonaws.com')) ,
            managedPolicies: [iam.ManagedPolicy.fromManagedPolicyArn(this, 'AWSLambdaBasicExecutionRole', 'arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole')],
        });
    }

    createLambdaEdgeWithDdbAdmin() {
        const role = new iam.Role(this, 'lambdaEdgeDdbExecutionRole', {
            assumedBy: new iam.CompositePrincipal(new iam.ServicePrincipal('edgelambda.amazonaws.com'), new iam.ServicePrincipal('lambda.amazonaws.com')) ,
            managedPolicies: [
                iam.ManagedPolicy.fromManagedPolicyArn(this, 'AWSLambdaDdbExecutionRole', 'arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole'),
            ],
        });
        role.addToPolicy(new iam.PolicyStatement({
            effect: iam.Effect.ALLOW,
            resources: ['*'],
            actions: ['dynamodb:*']
        }))
        return role
    }

    createOrigin(mediaCf: MediaCloudFront): cf.IOrigin {
        if(mediaCf.s3Origin) {
            return this.createS3Origin(mediaCf.s3Origin)
        } else if(mediaCf.httpOrigin) {
            return new origins.HttpOrigin(mediaCf.httpOrigin.domainName, mediaCf.httpOrigin.originProps)
        } else {
            throw new Error("no origin")
        }
    }

    createS3Origin(s3Origin: S3OriginInfo): origins.S3Origin {
        const s3Bucket = s3.Bucket.fromBucketAttributes(this, 'originS3', {
            bucketArn: s3Origin.bucketArn,
            region: s3Origin.region,
        })
        return new origins.S3Origin(s3Bucket, {
            originAccessIdentity: cf.OriginAccessIdentity.fromOriginAccessIdentityId(this, 'oai', s3Origin.originAccessIdentityId),
            originPath: s3Origin.originPath
        })
    }

    createLiveManifestCachePolicy(cachePolicy: cf.CachePolicyProps = {
        minTtl: Duration.seconds(5),
        maxTtl: Duration.minutes(3),
        defaultTtl: Duration.seconds(6),
        headerBehavior: cf.CacheHeaderBehavior.allowList('Origin'),
        enableAcceptEncodingGzip: true,
        enableAcceptEncodingBrotli: true,
    }): cf.CachePolicy {
        return new cf.CachePolicy(this, 'liveManifestCachePolicy', cachePolicy)
    }

    createLambdaFromFile(lambdaEdgeBasicExecutionRole: iam.Role, name: string, inlineCode: string, timeout: Duration = Duration.seconds(15)): lambda.Function {
        const code = lambda.Code.fromInline(inlineCode)
        return new lambda.Function(this, name, {
            runtime: lambda.Runtime.NODEJS_16_X,
            handler: 'index.handler',
            role: lambdaEdgeBasicExecutionRole,
            code: code,
            timeout: timeout,
        });
    }
}

