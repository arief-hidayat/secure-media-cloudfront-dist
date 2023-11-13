'use strict';
const AWS = require('aws-sdk');
const qs = require("querystring");
const masterManifests = 'MASTER_MANIFESTS';

exports.handler = (event, context, callback) => {
    const request = event.Records[0].cf.request;
    const viewerDomain = event.Records[0].cf.config.distributionDomainName;
    const paths = request.uri.split("/")
    const queryStrings = qs.parse(request.querystring)
    const duration = queryStrings['duration'] ? parseInt(queryStrings['duration']) : 300;
    const key = paths[paths.length - 1]
    if(!masterManifests[key]) {
        callback(
            null,
            {
                'status': '403',
                'statusDescription': 'Forbidden',
                'headers': {
                    'content-type': [{'key': 'Content-Type', 'value': 'text/plain'}]
                },
                'body': ''
            }
        );
    }
    callback(
        null,
        {
            'status': '201',
            'statusDescription': 'Created',
            'headers': {
                'content-type': [{'key': 'Content-Type', 'value': 'text/plain'}]
            },
            'body': signed(viewerDomain, masterManifests[key], duration)
        }
    );
};

function getEpochTime() {
    return Math.floor(new Date().getTime() / 1000)
}

function signed(domain, uri, duration) {
    let keyPairId = 'KEY_PAIR_ID';
    let privateKey = `PRIVATE_KEY`;
    let cf = new AWS.CloudFront.Signer(keyPairId, privateKey);
    let policy = JSON.stringify({
        Statement: [{
            Resource: 'https://'+ domain+uri,
            Condition: {
                DateLessThan: {
                    'AWS:EpochTime': getEpochTime() + duration
                }
            }
        }]
    });
    let signedUrl= cf.getSignedUrl({'url': 'https://'+ domain+uri, 'policy': policy});
    let qry = signedUrl.split('?').pop();
    return 'https://'+ domain+uri+'?'+qry;
}