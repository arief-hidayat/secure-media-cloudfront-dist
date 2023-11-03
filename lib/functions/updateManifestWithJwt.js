'use strict';
const https = require('https');
const AWS = require('aws-sdk');
const crypto = require("crypto");
const net = require("node:net");
const qs = require("querystring");

const KEYS = 'JWT_KEYS';

class Base64Url {

    // Copyright (c) 2013–2016 Brian J. Brennan
    //
    // Permission is hereby granted, free of charge, to any person obtaining a
    // copy of this software and associated documentation files (the
    // "Software"), to deal in the Software without restriction, including
    // without limitation the rights to use, copy, modify, merge, publish,
    // distribute, sublicense, and/or sell copies of the Software, and to
    // permit persons to whom the Software is furnished to do so, subject to
    // the following conditions:
    //
    //     The above copyright notice and this permission notice shall be included
    // in all copies or substantial portions of the Software.
    //
    // THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
    // OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
    // MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
    // NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
    // LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
    // OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
    // WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
    static encode(input) {
        return Base64Url.fromBase64(Buffer.from(input, "utf8").toString("base64"));
    };

    static decode(base64url) {
        return Buffer.from(Base64Url.toBase64(base64url), "base64").toString("utf8");
    }

    static toBase64(base64url) {
        return Base64Url.padString(base64url)
            .replace(/-/g, "+")
            .replace(/_/g, "/");
    }

    static fromBase64(base64) {
        return base64
            .replace(/=/g, "")
            .replace(/\+/g, "-")
            .replace(/\//g, "_");
    }


    static padString(input) {
        let segmentLength = 4;
        let stringLength = input.length;
        let diff = stringLength % segmentLength;

        if (!diff) {
            return input;
        }

        let position = stringLength;
        let padLength = segmentLength - diff;
        let paddedStringLength = stringLength + padLength;
        let buffer = Buffer.alloc(paddedStringLength);

        buffer.write(input);

        while (padLength--) {
            buffer.write("=", position++);
        }

        return buffer.toString();
    }
}
class TokenValidator {
    static _debug = false;
    logger(message){
        if(this._debug || this._debug === undefined) console.log("[DEBUG] " + message);
    }
    constructor(keys){
        this.keys = keys;
    }
     _verifySignature(input, key, method, type, signature) {
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
        return Base64Url.decode(str);
    }
     _verifyIntSig(payloadJwt, intSigKey, method, type, sessionId, headers, qs, requestIP) { // nosonar
        var indirectAttr = ''; // nosonar
        //recreating signing input based on JWT payload claims and request attributes
        if (payloadJwt['ip']){
            if (requestIP){
                indirectAttr += (requestIP + ':');
            } else {
                throw new Error('intsig reference error: Request IP is missing');
            }
        }
        if (payloadJwt['co']){
            if (headers['cloudfront-viewer-country']){
                indirectAttr += (headers['cloudfront-viewer-country'][0].value + ':');
            } else if(payloadJwt['co_fallback']) {
                this.logger("Viewer country header missing but co_fallback set to true. Skipping internal signature verification");
                return true;
            } else {
                throw new Error('intsig reference error: cloudfront-viewer-country header is missing');
            }
        }
        if (payloadJwt['reg']){
            if (headers['cloudfront-viewer-country-region']){
                indirectAttr += (headers['cloudfront-viewer-country-region'][0].value + ':');
            } else if(payloadJwt['reg_fallback']) {
                this.logger("Viewer country region header missing but reg_fallback set to true. Skipping internal signature verification");
                return true;
            } else {
                throw new Error('intsig reference error: cloudfront-viewer-country-region header is missing');
            }
        }
        if (payloadJwt['ssn']){
            if (sessionId){
                indirectAttr += sessionId + ':';
            } else {
                throw new Error('intsig reference error: Session id is missing');
            }
        }
        if(payloadJwt['headers']) payloadJwt.headers.forEach( attribute => {
            if (headers[attribute]){
                indirectAttr += (headers[attribute][0].value + ':' );
            }
        });
        if(payloadJwt['qs']) payloadJwt.qs.forEach( attribute => {
            if (qs[attribute]){
                indirectAttr += (qs[attribute].value + ':' );
            }
        });
        indirectAttr = indirectAttr.slice(0,-1);
        if (indirectAttr && !this._verifySignature(indirectAttr, intSigKey, method, type, payloadJwt['intsig'])) {
            this.logger("Indirect attributes input string:" + indirectAttr);
            return false;
        } else {
            return true;
        }
    }
     checkJWTToken(token, uri, sessionId, headers, qs, ip, noVerify) { // nosonar
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
            if (!this._verifySignature(signingInput, this.keys[header.kid], signingMethod, signingType, signatureSeg)) {
                throw new Error('JWT signature verification failed');
            }
            if (payload.exp && Date.now() > payload.exp*1000) {
                this.logger(`JWT expiry: ${payload.exp}, current time: ${Date.now}`);
                tokenActive = false;
            }
            if (payload.nbf && Date.now() < payload.nbf*1000) {
                this.logger(`JWT nbf: ${payload.nbf}, current time: ${Date.now}`);
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
                    this.logger(`request uri: ${uri}`)
                    throw new Error('URI path doesn\'t match any path in the token');
                }
            }
            var fullIP; // nosonar
            if(payload['ip']){
                if(!payload['ip_ver']) throw new Error("Missing ip_ver claim required when ip claim is set to true");
                if(parseInt(payload['ip_ver']) !== 4 && parseInt(payload['ip_ver'] !== 6)) throw new Error("Incorrect ip_ver claim value. Must be either 4 or 6");
                if(ip.includes('.')){
                    if(payload['ip_ver'] !== 4) throw new Error("Viewer's IP version (4) doesn't match ip_ver claim");
                    fullIP = ip;
                } else if(ip.includes(':')){
                    if(payload['ip_ver'] !== 6) throw new Error("Viewer's IP version (6) doesn't match ip_ver claim");
                    var hextets = ip.split(':').map(item => { return(item.length ? Array(5-item.length).join('0')+item : '')}); // nosonar
                    fullIP = hextets.join(':');
                } else {
                    throw new Error("Viewer's IP version not recognized");
                }
            }
            if (payload['intsig'] && !this._verifyIntSig(payload, this.keys[header.kid], signingMethod, signingType, sessionId, headers, qs, fullIP)) {
                throw new Error('Internal signature verification failed');
            }
        }
        return {
            keyId: header.kid,
            tokenActive: tokenActive
        };
    }
}
class TokenGenerator {
    static _debug = false;
    logger(message){
        if(TokenGenerator._debug || TokenGenerator._debug === undefined) console.log("[DEBUG] " + message);
    }

    constructor(keys, defaultTokenPolicy=null){
        this.keys = keys;
        this.defaultTokenPolicy = defaultTokenPolicy;
    }

    static setDEBUG(val=true){ // NOSONAR - javascript:S4144 - functions are in separate classes. Issue is not significant enough to refactor.
        if(typeof(val)=='boolean'){
            this._debug = val;
        }
    }
    _expandIPv6(address){
        let hextetsAbbrev = address.split(':');
        if (hextetsAbbrev.slice(-1) === '') {
            hextetsAbbrev.pop();  //when prefix ends with :: this creates two empty elements in an array
        }
        if (hextetsAbbrev[0] === '') {
            hextetsAbbrev.shift();  //when prefix starts with :: this creates two empty elements in an array
        }
        //add leading zeros in extets and expand two-collon (::) notation
        let hextets = hextetsAbbrev.map(item => { return(item.length ? Array(5-item.length).join('0')+item : '')});
        if(hextets.indexOf('')>-1) {
            hextets.splice.apply(hextets,[hextets.indexOf(''),1].concat(Array(9-hextets.length).fill('0000')));
        }
        return hextets.join(':');
    }

    _populateIP(viewerAttributes, jwtPayload) {
        let fullIP;
        if(viewerAttributes['ip'].includes('.') && net.isIPv4(viewerAttributes['ip'])){
            jwtPayload['ip_ver']=4;
            fullIP = viewerAttributes['ip'];
        } else if(net.isIPv6(viewerAttributes['ip'])){
            jwtPayload['ip_ver']=6;
            fullIP = this._expandIPv6(viewerAttributes['ip']);
        } else {
            throw new Error("Invalid viewer's IP format");
        }
        return { fullIP: fullIP, jwtPayload: jwtPayload };
    }
    _populateBooleanItems(tokenPolicy, viewerAttributes, jwtPayload) {
        let intSigInput = '';
        if (tokenPolicy['ip']) {
            const populateIP = this._populateIP(viewerAttributes, jwtPayload);
            jwtPayload = populateIP.jwtPayload;
            jwtPayload['ip'] = true;
            intSigInput += populateIP.fullIP + ':';
        }
        if (tokenPolicy['co']){
            jwtPayload['co']=true;
            intSigInput += viewerAttributes['co'] + ':';
            if(tokenPolicy['co_fallback']) jwtPayload['co_fallback']=true;
        }
        if (tokenPolicy['cty']){
            jwtPayload['cty']=true;
            intSigInput += viewerAttributes['cty'] + ':';
        }
        if (tokenPolicy['reg']){
            jwtPayload['reg']=true;
            intSigInput += viewerAttributes['reg'] + ':';
            if(tokenPolicy['reg_fallback']) jwtPayload['reg_fallback']=true;
        }
        if (tokenPolicy['ssn']){
            jwtPayload['ssn']=true;
            if (viewerAttributes['sessionId']) {
                this.payloadSsn = viewerAttributes['sessionId'];
            }
            else {
                // let session = new Session(tokenPolicy['session_auto_generate'],true);
                this.payloadSsn = AWS.util.uuid.v4();
            }
            intSigInput += this.payloadSsn + ':';
        }
        return { jwtPayload: jwtPayload, intSigInput: intSigInput };
    }
    _populateExp(tokenPolicy, jwtPayload) {
        if(tokenPolicy['exp'].startsWith('+')){
            if(tokenPolicy['exp'].endsWith('h')){
                jwtPayload['exp'] = parseInt(Date.now()/1000) + parseInt(tokenPolicy['exp'].slice(1,-1))*3600;
            } else if(tokenPolicy['exp'].endsWith('m')){
                jwtPayload['exp'] = parseInt(Date.now()/1000) + parseInt(tokenPolicy['exp'].slice(1,-1))*60;
            } else {
                throw new Error("Invalid exp format");
            }
        } else {
            let parsedExp = parseInt(tokenPolicy['exp']);
            if(parsedExp <= 0){
                throw new Error("Invalid exp format");
            }
            jwtPayload['exp'] = parsedExp;
        }
        return jwtPayload;
    }
    _populateJwtPayload(tokenPolicy, viewerAttributes, jwtPayload, playbackUrlQs, key) {
        const booleanItems = this._populateBooleanItems(tokenPolicy, viewerAttributes, jwtPayload);
        jwtPayload = booleanItems.jwtPayload;
        let intSigInput = booleanItems.intSigInput;
        if (tokenPolicy['headers'] && tokenPolicy['headers'].length){
            tokenPolicy['headers'].forEach((header)=>{
                jwtPayload['headers'].push(header);
                if(viewerAttributes['headers'][header]) intSigInput += viewerAttributes['headers'][header][0].value + ':';
            });
        }
        if (tokenPolicy['querystrings'] && tokenPolicy['querystrings'].length){
            tokenPolicy['querystrings'].forEach((qsParam)=>{
                jwtPayload['qs'].push(qsParam);
                let qs_value = playbackUrlQs[qsParam] || viewerAttributes['qs'][qsParam];
                if(qs_value) intSigInput += qs_value + ':';
            });
        }
        if(intSigInput){
            intSigInput = intSigInput.slice(0,-1);
            this.logger("Input for internal signature: " + intSigInput);
            jwtPayload['intsig'] = this._sign(intSigInput, key, 'sha256')
        } else {
            delete jwtPayload['intsig'];
        }
        jwtPayload['paths'] = tokenPolicy['paths'];
        if (tokenPolicy['exc']) jwtPayload['exc'] = tokenPolicy['exc'];
        if (tokenPolicy['nbf']) jwtPayload['nbf'] = parseInt(tokenPolicy['nbf']);
        jwtPayload = this._populateExp(tokenPolicy, jwtPayload);
        return jwtPayload;
    }
    _b64url(input) {
        return Base64Url.encode(input);
    }

    _sign(input, key, method){
        return this._b64url(crypto.createHmac(method, key).update(input).digest());
    }
    _jwtSign(keyId, jwtPayload) {
        const headers = {
            "alg": "HS256",
            "typ": "JWT",
            "kid": keyId
        }
        const encodedHeader = this._b64url(JSON.stringify(headers));
        const encodedPayload = this._b64url(JSON.stringify(jwtPayload));
        const token = encodedHeader + "." + encodedPayload;
        const signature = this._sign(token, this.keys[keyId], "sha256");
        return token + "." + signature;
    }
    generate(keyId, viewerAttributes, playbackUrl=null, tokenPolicy){
        let playbackUrlQs = {};
        if(playbackUrl){
            playbackUrlQs = qs.parse(playbackUrl);
        }
        let jwtPayload = {
            ip: false,
            co: false,
            cty: false,
            reg: false,
            ssn: false,
            exp: '',
            headers: [],
            qs: [],
            intsig: '',
            paths: [],
            exc: []
        }
        jwtPayload = this._populateJwtPayload(tokenPolicy, viewerAttributes, jwtPayload, playbackUrlQs, this.keys[keyId]);
        this.encoded_jwt = this._jwtSign(keyId, jwtPayload);
        if(playbackUrl){
            let playback_url_array = playbackUrl.split('/');
            playback_url_array.splice(3,0,`${this.payloadSsn?this.payloadSsn+'.':''}${this.encoded_jwt}`);
            this.output_playback_url = playback_url_array.join('/');
            return this.output_playback_url;
        }
        return `${this.payloadSsn?this.payloadSsn+'.':''}${this.encoded_jwt}`;
    }
}

class ViewerAttributes {
    constructor(tokenPolicy, headers, qs, clientIp = null){
        this.tokenPolicy = tokenPolicy;
        this.headers = headers;
        this.qs = qs;
        this.clientIp = clientIp;
        this.viewerAttributes = {};
    }
    get() {
        this._populateViewerAttributes();
        return this.viewerAttributes;
    }

    _getViewerIp() {
        if(this.headers['cloudfront-viewer-address']){
            return this.headers['cloudfront-viewer-address'].substring(0, this.headers['cloudfront-viewer-address'].lastIndexOf(':'))
        } else {
            return this.clientIp;
        }
    }
    _populateCountryRegionCity() {
        if(this.tokenPolicy['co']){
            if(this.headers['cloudfront-viewer-country']){
                this.viewerAttributes['co'] = this.headers['cloudfront-viewer-country'];
            } else if(!this.tokenPolicy['co_fallback']) {
                throw new Error("missing co");
            }
        }
        if(this.tokenPolicy['reg']){
            if(this.headers['cloudfront-viewer-country-region']){
                this.viewerAttributes['reg'] = this.headers['cloudfront-viewer-country-region'];
            } else if(!this.tokenPolicy['reg_fallback']) {
                throw new Error("missing co");
            }
        }
        if(this.tokenPolicy['cty']){
            if(this.headers['cloudfront-viewer-city']){
                this.viewerAttributes['cty'] = this.headers['cloudfront-viewer-city'];
            } else if(!this.tokenPolicy['cty_fallback']) {
                throw new Error("missing co");
            }
        }
    }

    _populateViewerAttributes() {
        this._populateCountryRegionCity();
        // if (viewerAttributes.statusCode) return viewerAttributes;
        if(this.tokenPolicy['ip']) {
            this.viewerAttributes['ip'] = this._getViewerIp();
        }
        if(this.tokenPolicy['headers'] && this.tokenPolicy['headers'].length > 0){
            this.viewerAttributes['headers'] = this.headers;
        }
        if(this.tokenPolicy['querystrings'] && this.tokenPolicy['querystrings'].length > 0){
            this.viewerAttributes['qs'] = this.qs;
        }
    }
}

class Responses {
    static create(status, statusDesc, body) {
        return  {
            'status': status,
            'statusDescription': statusDesc,
            'headers': {
                'content-type': [{'key': 'Content-Type', 'value': 'text/plain'}]
            },
            'body': body
        }
    }
    static with400(bodyStr) {
        return Responses.create('400', 'Bad Request', bodyStr)
    }
    static with403(bodyStr) {
        return Responses.create('403', 'Forbidden', bodyStr)
    }
    static with500(bodyStr) {
        return Responses.create('500', 'Internal Error', bodyStr)
    }
}

function getSessionJwtToken(uri, qs) {
    let pathArray = uri.split('/'); // nosonar
    const authTokenQsExists = qs && qs['auth_token']
    const authSeq = authTokenQsExists ? qs['auth_token'] : pathArray[1]; // nosonar
    if(!authSeq || pathArray.length < 3){
        throw new Error('Error: No token is present')
    }
    const authSeqArr = authSeq.split('.'); // nosonar

    const sessionId = authSeqArr.length === 4 ? authSeqArr.shift() : ""; // nosonar
    const jwtToken = authSeqArr.join('.'); // nosonar
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
            newUri: uri,
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
    const queryStrings = qs.parse(request.querystring);
    let newDirPath = "";
    let newUri = "";
    let needToModifyPath = false;
    let viewerAttributes = {}
    let viewerDomain = 'VIEWER_DOMAIN_NAME';
    const tokenPolicy = {
        exp: "TOKEN_TTL",
        ssn: false,
        headers: ["user-agent", "referer"]
    }
    try {
        viewerAttributes = new ViewerAttributes(tokenPolicy, request.headers, queryStrings, request.clientIp).get();
        if(viewerDomain === "") {
            viewerDomain = event.Records[0].cf.config.distributionDomainName;
        }
    } catch(e) {
        callback(null, Responses.with400(e.message));
        return;
    }
    let keyId = '';
    try {
        const sessJwtUri = getSessionJwtToken(request.uri, queryStrings);
        newDirPath = sessJwtUri.newDirPath;
        newUri = sessJwtUri.newUri;
        needToModifyPath = sessJwtUri.tokenInUrlPath;
        if (sessJwtUri.sessionId) {
            tokenPolicy.ssn = true
        }
        const tokenValidator = new TokenValidator(KEYS);
        const tokenVal = tokenValidator.checkJWTToken(sessJwtUri.jwtToken, newUri, sessJwtUri.sessionId, request.headers, queryStrings, viewerAttributes['ip']);
        keyId = tokenVal.keyId;
    } catch(e) {
        callback(null, Responses.with403(e.message));
        return;
    }
    let authToken = '';
    try {
        const tokenGenerator = new TokenGenerator(KEYS, tokenPolicy);
        authToken = tokenGenerator.generate(keyId, viewerAttributes, null, tokenPolicy);
    } catch(e) {
        callback(null, Responses.with403(e.message));
    }

    let response = {};
    const manifestUrl = 'https://MANIFEST_DOMAIN_NAME';
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
        const pattern = /(media|initialization)(\s*)=(\s*)"([^"]+)"/g;
        const replacement = needToModifyPath ? `$1="https://${viewerDomain}/${authToken}${newDirPath}/$4"` : `$1="$4?auth_token=${authToken}"`
        resp.on('end', () => {
            data.split("\n").forEach((elem)=> {
                if(newUri.endsWith(".mpd")) {
                    if (elem.indexOf(".mp4") !== -1 ) {
                        body.push(elem.replace(pattern, replacement));
                    } else {
                        body.push(elem);
                    }
                } else {
                    if (elem.startsWith("#") ) {
                        if(elem.indexOf("URI") !== -1) { //URI component inline
                            var uriComponents = elem.substring(elem.indexOf("URI")).split("\"");
                            if(uriComponents.indexOf(".m3u8")) {
                                body.push(elem);
                            } else {
                                uriComponents[1] = needToModifyPath ? `https://${viewerDomain}/${authToken}${newDirPath}/${uriComponents[1]}` : `${uriComponents[1]}?auth_token=${authToken}`;
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
                            body.push(needToModifyPath ? `https://${viewerDomain}/${authToken}${newDirPath}/${elem}` : `${elem}?auth_token=${authToken}`);
                        }
                    }
                }
            });
            response.body = body.join('\n');
            callback(null, response);
        });
    }).on('error', (err)=>{
        callback(null, Responses.with500('Error reading content \n\n'+err));
    });
};