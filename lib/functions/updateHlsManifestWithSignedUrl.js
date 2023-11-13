'use strict';
const https = require('https');
const AWS = require('aws-sdk');
const path = require('path');
const qs = require("querystring");

exports.handler = (event, context, callback) => {
    const request = event.Records[0].cf.request;
    const manifestDomainUrl = 'https://MANIFEST_DOMAIN_NAME';
    let viewerDomain = 'VIEWER_DOMAIN_NAME';
    if(viewerDomain === "") {
        viewerDomain = event.Records[0].cf.config.distributionDomainName;
    }
    let response = {};
    //find dir for the m3u8
    let dir = path.dirname(request.uri);

    const queryStrings = qs.parse(request.querystring);
    if(queryStrings['Policy']) {
        delete queryStrings['Policy']
    }
    if(queryStrings['Key-Pair-Id']) {
        delete queryStrings['Key-Pair-Id']
    }
    if(queryStrings['Signature']) {
        delete queryStrings['Signature']
    }
    let querystring = qs.stringify(queryStrings);
    // let querystring = (request.querystring)?"?"+request.querystring:"";
    //request to 2nd CF to get cached m3u8
    https.get(manifestDomainUrl+request.uri+querystring, (resp) => {
        //use same status code
        response.status = resp.statusCode;
        //respond with a few headers
        let headers = {
            "content-type": [{"key": "Content-Type", "value": resp.headers["content-type"]||"text/html"}],
            "server": [{"key": "Server", "value": resp.headers["server"]||"Server"}]
        };
        const corsResponse = 'CORS_RESPONSE'
        if(corsResponse.length > 0) {
            headers['access-control-allow-origin'] = [{"key": "Access-Control-Allow-Origin", "value": corsResponse}]
        }
        response.headers = headers;

        //load response to <data>
        let data = "";
        resp.on('data', (chunk) => {
            data += chunk;
        });
        //create signed URL only for lines without initial #, or URI component
        let body = [];
        let cf = getSigner();
        resp.on('end', () => {
            data.split("\n").forEach((elem)=> {
                if (elem.startsWith("#") ) {
                    if(elem.indexOf("URI") !== -1) { //URI component inline
                        var uriComponents = elem.substring(elem.indexOf("URI")).split("\"");
                        uriComponents[1] = signed(cf, viewerDomain, dir, uriComponents[1]);
                        body.push(elem.substring(0,elem.indexOf("URI"))+uriComponents.join("\""));
                    }
                    else {
                        body.push(elem);
                    }
                }
                else if(elem === "") {
                    body.push(elem);
                }
                else {
                    body.push(signed(cf, viewerDomain, dir, elem));
                }
            });
            response.body = body.join('\n');
            callback(null, response);
        });
    }).on('error', (err)=>{
        callback(
            null,
            {
                'status': '500',
                'statusDescription': 'Server Error',
                'headers': {
                    'content-type': [{'key': 'Content-Type', 'value': 'text/plain'}]
                },
                'body': 'Error reading content \n\n'+err
            }
        );
    });

};

function getEpochTime() {
    return Math.floor(new Date().getTime() / 1000)
}

function getSigner() {
    let keyPairId = 'KEY_PAIR_ID';
    let privateKey = `PRIVATE_KEY`;
    return new AWS.CloudFront.Signer(keyPairId, privateKey);
}

function signed(cf, domain, dir, file) {
    let duration = 300;

    let policy = JSON.stringify({
        Statement: [{
            Resource: 'https://'+ domain+path.posix.join(dir,file),
            Condition: {
                DateLessThan: {
                    'AWS:EpochTime': getEpochTime() + duration
                }
            }
        }]
    });

    let signedUrl= cf.getSignedUrl({'url': 'https://'+ domain+path.posix.join(dir,file), 'policy': policy});

    let qry = signedUrl.split('?').pop();

    return file+'?'+qry;
}