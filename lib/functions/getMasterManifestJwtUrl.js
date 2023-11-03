'use strict';
const AWS = require('aws-sdk');
const crypto = require("crypto");
const net = require("node:net");
const qs = require("querystring");

const KEYS = 'JWT_KEYS';
const MASTER_MANIFESTS = 'MASTER_MANIFESTS';

class Base64Url {

    // _base64urlDecode(input) {
    //     return Buffer.from(input, "utf8").toString("base64")
    //         .replace(/=/g, "")
    //         .replace(/\+/g, "-")
    //         .replace(/\//g, "_");
    // }
    // static decode(str) {
    //     return Buffer.from(Base64Url._decodeString(str), 'base64').toString();
    // }
    // static _decodeString(input) {
    //     input = input
    //         .replace(/-/g, '+')
    //         .replace(/_/g, '/');
    //
    //     // Pad out with standard base64 required padding characters
    //     var pad = input.length % 4;
    //     if(pad) {
    //         if(pad === 1) {
    //             throw new Error('InvalidLengthError: Input base64url string is the wrong length to determine padding');
    //         }
    //         input += new Array(5-pad).join('=');
    //     }
    //     return input;
    // }

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
    // The above copyright notice and this permission notice shall be included
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
            this.logger("Input for internal signature: ", intSigInput);
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
    static with201(bodyStr) {
        return Responses.create('201', 'Created', bodyStr)
    }
    static with400(bodyStr) {
        return Responses.create('400', 'Bad Request', bodyStr)
    }
    static with403(bodyStr) {
        return Responses.create('403', 'Forbidden', bodyStr)
    }
}

exports.handler = (event, context, callback) => {
    const request = event.Records[0].cf.request;
    const uri = request.uri;
    const queryStrings = qs.parse(request.querystring)

    const paths = uri.split("/")
    const manifestKey = paths[paths.length - 1]
    if(!MASTER_MANIFESTS[manifestKey]) {
        callback(null, Responses.with403('invalid manifest key'));
        return;
    }
    const keyId = queryStrings["kid"] ?queryStrings["kid"]: "";
    if(!KEYS[keyId]) {
        callback(null, Responses.with403('invalid key'));
        return;
    }
    const tokenPolicy = {
        exp: queryStrings["exp"] ? queryStrings["exp"]: "TOKEN_TTL",
        ssn: !(queryStrings["ssn"] && queryStrings["ssn"] === "false"),
        headers: ["user-agent", "referer"]
    }
    let viewerAttributes = {}
    let viewerDomain = 'VIEWER_DOMAIN_NAME';
    try {
        viewerAttributes = new ViewerAttributes(tokenPolicy, request.headers, queryStrings, request.clientIp).get();
        if(viewerDomain === "") {
            viewerDomain = event.Records[0].cf.config.distributionDomainName;
        }
    } catch(e) {
        callback(null, Responses.with400(e.message));
        return;
    }
    try {
        const tokenGenerator = new TokenGenerator(KEYS, tokenPolicy);
        const originalPlaybackUrl = `https://${viewerDomain}${MASTER_MANIFESTS[manifestKey]}`
        callback(null, Responses.with201(tokenGenerator.generate(keyId, viewerAttributes, originalPlaybackUrl, tokenPolicy)));
    } catch(e) {
        callback(null, Responses.with403(e.message));
    }
};