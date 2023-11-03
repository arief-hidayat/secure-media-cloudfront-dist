'use strict';
const https = require('https');
const AWS = require('aws-sdk');
const crypto = require("crypto");
const path = require("path");
const qs = require("querystring");

// master manifest using token in url path or in auth_token query param.
// child manifest without token in url path but using signed URL query param.
const KEYS = 'JWT_KEYS'
function log(message){
    if(this._debug || this._debug === undefined) console.log("[DEBUG] " + message);
}

class TokenValidator {
    static _debug = false;
    static logger = log;
    constructor(keys){
        this.keys = keys;
    }
     _verify_signature(input, key, method, type, signature) {
        if(type === "hmac") {
            return (signature === this._sign(input, key, method));
        }
        else {
            throw new Error('Algorithm type not recognized');
        }
    }
    _sign(input, key, method) {
        return crypto.createHmac(method, key).update(input).digest('base64url');
    }
    _base64urlDecode(str) {
        return Buffer.from(this._decodeString(str), 'base64').toString();
    }
    _decodeString(input) {
        input = input
            .replace(/-/g, '+')
            .replace(/_/g, '/');

        // Pad out with standard base64 required padding characters
        var pad = input.length % 4;
        if(pad) {
            if(pad === 1) {
                throw new Error('InvalidLengthError: Input base64url string is the wrong length to determine padding');
            }
            input += new Array(5-pad).join('=');
        }
        return input;
    }
     _verify_intsig(payload_jwt, intsig_key, method, type, sessionId, request_headers, request_querystrings, request_ip) { // nosonar
        var indirect_attr = ''; // nosonar
        //recreating signing input based on JWT payload claims and request attributes
        if (payload_jwt['ip']){
            if (request_ip){
                indirect_attr += (request_ip + ':');
            } else {
                throw new Error('intsig reference error: Request IP is missing');
            }
        }
        if (payload_jwt['co']){
            if (request_headers['cloudfront-viewer-country']){
                indirect_attr += (request_headers['cloudfront-viewer-country'][0].value + ':');
            } else if(payload_jwt['co_fallback']) {
                TokenValidator.logger("Viewer country header missing but co_fallback set to true. Skipping internal signature verification");
                return true;
            } else {
                throw new Error('intsig reference error: cloudfront-viewer-country header is missing');
            }
        }
        if (payload_jwt['reg']){
            if (request_headers['cloudfront-viewer-country-region']){
                indirect_attr += (request_headers['cloudfront-viewer-country-region'][0].value + ':');
            } else if(payload_jwt['reg_fallback']) {
                TokenValidator.logger("Viewer country region header missing but reg_fallback set to true. Skipping internal signature verification");
                return true;
            } else {
                throw new Error('intsig reference error: cloudfront-viewer-country-region header is missing');
            }
        }
        if (payload_jwt['ssn']){
            if (sessionId){
                indirect_attr += sessionId + ':';
            } else {
                throw new Error('intsig reference error: Session id is missing');
            }
        }
        if(payload_jwt['headers']) payload_jwt.headers.forEach( attribute => {
            if (request_headers[attribute]){
                indirect_attr += (request_headers[attribute][0].value + ':' );
            }
        });
        if(payload_jwt['qs']) payload_jwt.qs.forEach( attribute => {
            if (request_querystrings[attribute]){
                indirect_attr += (request_querystrings[attribute].value + ':' );
            }
        });
        indirect_attr = indirect_attr.slice(0,-1);
        if (indirect_attr && !this._verify_signature(indirect_attr, intsig_key, method, type, payload_jwt['intsig'])) {
            TokenValidator.logger("Indirect attributes input string:" + indirect_attr);
            return false;
        } else {
            return true;
        }
    }
     checkJWTToken(token, uri, session_id, http_headers, querystrings, ip, noVerify) { // nosonar
        // check segments
        var segments = token.split('.'); // nosonar
        if (segments.length !== 3) {
            throw new Error('Not enough or too many segments in JWT token');
        }
        // All segment should be base64url
        var headerSeg = segments[0]; // nosonar
        var payloadSeg = segments[1]; // nosonar
        var signatureSeg = segments[2]; // nosonar
        // base64url decode and parse JSON
        var header; // nosonar
        var payload; // nosonar
        try{
            header = JSON.parse(this._base64urlDecode(headerSeg));
            payload = JSON.parse(this._base64urlDecode(payloadSeg));
        } catch(e){
            throw new Error('malformed JWT token');
        }
         if(!header.kid) {
             throw new Error('missing kid');
         }
         var tokenActive = true;
        if (!noVerify) {
            var alg = header['alg']; // nosonar
            var signingMethod; // nosonar
            var signingType; // nosonar
            if (alg==='HS256'){
                signingMethod = 'sha256';
                signingType = 'hmac';
            } else {
                throw new Error('Missing or unsupported signing algorithm in JWT header');
            }
            // Verify signature. `sign` will return base64 string.
            var signingInput = [headerSeg, payloadSeg].join('.'); // nosonar
            if (!this._verify_signature(signingInput, this.keys[header.kid], signingMethod, signingType, signatureSeg)) {
                throw new Error('JWT signature verification failed');
            }
            if (payload.exp && Date.now() > payload.exp*1000) {
                TokenValidator.logger(`JWT expiry: ${payload.exp}, current time: ${Date.now}`);
                tokenActive = false;
            }
            if (payload.nbf && Date.now() < payload.nbf*1000) {
                TokenValidator.logger(`JWT nbf: ${payload.nbf}, current time: ${Date.now}`);
                tokenActive = false;
            }
            //check if request URL is not in the exclusion list and omit remaining validations if so
            if(payload.exc) {
                for (var i=0; i<payload.exc.length; i++){ // nosonar
                    if (uri.startsWith(payload.exc[i])) {
                        return payload;
                    }
                }
            }
            //validate if the request URL matches paths covered by the token
            if(payload.paths) {
                var uri_match = false; // nosonar
                for (var j=0; j<payload.paths.length; j++){ // nosonar
                    if (uri.startsWith(payload.paths[j])) {
                        uri_match = true;
                        break;
                    }
                }
                if (!uri_match) {
                    TokenValidator.logger(`request uri: ${uri}`)
                    throw new Error('URI path doesn\'t match any path in the token');
                }
            }
            var full_ip; // nosonar
            if(payload['ip']){
                if(!payload['ip_ver']) throw new Error("Missing ip_ver claim required when ip claim is set to true");
                if(parseInt(payload['ip_ver']) !== 4 && parseInt(payload['ip_ver'] !== 6)) throw new Error("Incorrect ip_ver claim value. Must be either 4 or 6");
                if(ip.includes('.')){
                    if(payload['ip_ver'] !== 4) throw new Error("Viewer's IP version (4) doesn't match ip_ver claim");
                    full_ip = ip;
                } else if(ip.includes(':')){
                    if(payload['ip_ver'] !== 6) throw new Error("Viewer's IP version (6) doesn't match ip_ver claim");
                    var hextets = ip.split(':').map(item => { return(item.length ? Array(5-item.length).join('0')+item : '')}); // nosonar
                    full_ip = hextets.join(':');
                } else {
                    throw new Error("Viewer's IP version not recognized");
                }
            }
            if (payload['intsig'] && !this._verify_intsig(payload, this.keys[header.kid], signingMethod, signingType, session_id, http_headers, querystrings, full_ip)) {
                throw new Error('Internal signature verification failed');
            }
        }
        return {
            keyId: header.kid,
            tokenActive: tokenActive
        };
    }
}
function getViewerIp(request) {
    if(request.headers['cloudfront-viewer-address']){
        const address = request.headers['cloudfront-viewer-address'][0].value
        return address.substring(0, address.lastIndexOf(':'))
    } else {
        return request.clientIp;
    }
}
function getSessionJwtToken(request) {
    let pathArray = request.uri.split('/'); // nosonar
    const queryStrings = qs.parse(request.querystring)
    const authTokenQsExists = queryStrings['auth_token']
    const auth_sequence = authTokenQsExists ? queryStrings['auth_token'] : pathArray[1]; // nosonar
    if(!auth_sequence || pathArray.length < 3){
        throw new Error('Error: No token is present')
    }
    const auth_sequence_array = auth_sequence.split('.'); // nosonar

    const sessionId = auth_sequence_array.length === 4 ? auth_sequence_array.shift() : ""; // nosonar
    const jwtToken = auth_sequence_array.join('.'); // nosonar
    //sanity check of the JWT token length
    if (jwtToken.length < 60) {
        throw new Error("Error: Invalid JWT token in the path");
    }
    if(authTokenQsExists) {
        pathArray.pop();
        return {
            tokenInUrlPath: false,
            sessionId: sessionId,
            jwtToken: jwtToken,
            newUri: request.uri,
            newDirPath: pathArray.join("/"),
        }
    }
    pathArray.splice(1,1);
    const newUri = pathArray.join("/");
    pathArray.pop();
    return {
        tokenInUrlPath: true,
        sessionId: sessionId,
        jwtToken: jwtToken,
        newUri: newUri,
        newDirPath: pathArray.join("/"),
    }
}

exports.handler = (event, context, callback) => {
    const request = event.Records[0].cf.request;
    const queryStrings = qs.parse(request.querystring)
    let newDirPath = "";
    let newUri = "";
    let needToModifyPath = false;
    try {
        const sessJwtUri = getSessionJwtToken(request);
        newDirPath = sessJwtUri.newDirPath;
        newUri = sessJwtUri.newUri;
        needToModifyPath = sessJwtUri.tokenInUrlPath;
        const tokenValidator = new TokenValidator(KEYS);
        tokenValidator.checkJWTToken(sessJwtUri.jwtToken, newUri, sessJwtUri.sessionId, request.headers, queryStrings, getViewerIp(request));
    } catch(e) {
        callback(
            null,
            {
                'status': '403',
                'statusDescription': 'Forbidden',
                'headers': {
                    'content-type': [{'key': 'Content-Type', 'value': 'text/plain'}]
                },
                'body': e.message
            }
        );
    }
    let viewerDomain = 'VIEWER_DOMAIN_NAME';
    if(viewerDomain === "") {
        viewerDomain = event.Records[0].cf.config.distributionDomainName;
    }
    const manifestUrl = 'https://MANIFEST_DOMAIN_NAME';
    let response = {};
    let querystring = (request.querystring)?"?"+request.querystring:"";
    //request to 2nd CF to get cached m3u8
    https.get(manifestUrl+newUri+querystring, (resp) => {
        response.status = resp.statusCode;
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
        let body = [];
        resp.on('end', () => {
            data.split("\n").forEach((elem)=> {
                if (elem.startsWith("#") ) {
                    if(elem.indexOf("URI") !== -1) { //URI component inline
                        var uriComponents = elem.substring(elem.indexOf("URI")).split("\"");
                        if(uriComponents.indexOf(".m3u8")) {
                            body.push(elem);
                        } else {
                            const signedVal = signed(viewerDomain, newDirPath, uriComponents[1])
                            uriComponents[1] = needToModifyPath ? `https://${viewerDomain}${newDirPath}/${signedVal}` : signedVal;
                            body.push(elem.substring(0,elem.indexOf("URI"))+uriComponents.join("\""));
                        }
                    }
                    else {
                        body.push(elem);
                    }
                }
                else if(elem=== "") {
                    body.push(elem);
                }
                else {
                    if(elem.indexOf(".m3u8") !== -1) {
                        body.push(elem);
                    } else {
                        const signedVal = signed(viewerDomain, newDirPath, elem)
                        body.push(needToModifyPath ? `https://${viewerDomain}${newDirPath}/${signedVal}` : signedVal);
                    }
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
function signed(domain, dir, file) {
    let keyPairId = 'KEY_PAIR_ID';
    let privateKey = `PRIVATE_KEY`;
    let duration = 300;
    let cf = new AWS.CloudFront.Signer(keyPairId, privateKey);
    const url = 'https://'+ domain+path.posix.join(dir,file)
    let policy = JSON.stringify({
        Statement: [{
            Resource: url,
            Condition: {
                DateLessThan: {
                    'AWS:EpochTime': getEpochTime() + duration
                }
            }
        }]
    });
    let signedUrl= cf.getSignedUrl({'url': url, 'policy': policy});
    let qry = signedUrl.split('?').pop();
    return file+'?'+qry;
}
