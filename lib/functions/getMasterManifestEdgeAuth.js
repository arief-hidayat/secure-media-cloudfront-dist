'use strict';
const crypto = require("crypto");
const qs = require("querystring");

const KEYS = 'TOKEN_KEYS';
const MASTER_MANIFESTS = 'MASTER_MANIFESTS';

class EdgeAuth {
    constructor(options) {
        this.options = options

        if (!this.options.tokenName) {
            this.options.tokenName = '__token__'
        }

        if (!this.options.key) {
            throw new Error('key must be provided to generate a token.')
        }

        if (this.options.algorithm === undefined) {
            this.options.algorithm = 'sha256'
        }

        if (this.options.escapeEarly === undefined) {
            this.options.escapeEarly = false
        }

        if (!this.options.fieldDelimiter) {
            this.options.fieldDelimiter = '~'
        }

        if (!this.options.aclDelimiter) {
            this.options.aclDelimiter = '!'
        }

        if (this.options.verbose === undefined) {
            this.options.verbose = false
        }
    }

    _escapeEarly(text) {
        if (this.options.escapeEarly) {
            text = encodeURIComponent(text)
                .replace(/[~'*]/g,
                    function(c) {
                        return '%' + c.charCodeAt(0).toString(16)
                    }
                )
            var pattern = /%../g
            text = text.replace(pattern, function(match) {
                return match.toLowerCase()
            })
        }
        return text
    }

    validateToken(urlPath, token) {
        var tokenParts = token.split(this.options.fieldDelimiter);
        if(tokenParts.length < 2) {
            throw new Error('no hmac')
        }
        var hmacEntry = tokenParts.pop().split('=', 2);
        if(hmacEntry.length !== 2 && hmacEntry[0] !== 'hmac') {
            throw new Error('no hmac')
        }
        // var withoutHmac = token.substring(0, hmacIndex).split(this.options.fieldDelimiter);
        var hashSource = tokenParts.slice()
        hashSource.push("url=" + this._escapeEarly(urlPath))
        if (this.options.salt) {
            hashSource.push("salt=" + this.options.salt)
        }
        this.options.algorithm = this.options.algorithm.toString().toLowerCase()
        if (!(this.options.algorithm == 'sha256' || this.options.algorithm == 'sha1' || this.options.algorithm == 'md5')) {
            throw new Error('algorithm should be sha256 or sha1 or md5')
        }
        var hmac = crypto.createHmac(
            this.options.algorithm,
            new Buffer(this.options.key, 'hex')
        )
        hmac.update(hashSource.join(this.options.fieldDelimiter))
        var actualHmacValue = hmac.digest('hex')
        var expectedHmacValue = hmacEntry[1];
        if(actualHmacValue !== expectedHmacValue) {
            throw new Error('hmac value not match')
        }
        var result = {
            valid: true,
            ip: '',
            id: '',
        }
        for (let i = 0; i < tokenParts.length; i++) {
            var entry = tokenParts[i].split('=', 2)
            if(entry.length !== 2) {
                throw new Error('invalid entry')
            }
            if(entry[0] === "exp") {
                try {
                    if (parseInt(Date.now()/1000) > parseInt(entry[1])) {
                        return {
                            valid: false
                        }
                    }
                } catch (e) {
                    throw new Error('valid parsing exp')
                }
            } else if(entry[0] === "ip") {
                result.ip = entry[1]
            } else if(entry[0] === "id") {
                result.id = entry[1]
            }
        }
        return result
    }

    _generateToken(path, isUrl) {
        var startTime = this.options.startTime
        var endTime = this.options.endTime

        if (typeof startTime === 'string' && startTime.toLowerCase() === 'now') {
            startTime = parseInt(Date.now() / 1000)
        } else if (startTime) {
            if (typeof startTime === 'number' && startTime <= 0) {
                throw new Error('startTime must be number ( > 0 ) or "now"')
            }
        }

        if (typeof endTime === 'number' && endTime <= 0) {
            throw new Error('endTime must be number ( > 0 )')
        }

        if (typeof this.options.windowSeconds === 'number' && this.options.windowSeconds <= 0) {
            throw new Error('windowSeconds must be number( > 0 )')
        }

        if (!endTime) {
            if (this.options.windowSeconds) {
                if (!startTime) {
                    startTime = parseInt(Date.now() / 1000)
                }
                endTime = parseInt(startTime) + parseInt(this.options.windowSeconds)
            } else {
                throw new Error('You must provide endTime or windowSeconds')
            }
        }

        if (startTime && (endTime < startTime)) {
            throw new Error('Token will have already expired')
        }

        if (this.options.verbose) {
            console.log("Akamai Token Generation Parameters")

            if (isUrl) {
                console.log("    URL         : " + path)
            } else {
                console.log("    ACL         : " + path)
            }

            console.log("    Token Type      : " + this.options.tokenType)
            console.log("    Token Name      : " + this.options.tokenName)
            console.log("    Key/Secret      : " + this.options.key)
            console.log("    Algo            : " + this.options.algorithm)
            console.log("    Salt            : " + this.options.salt)
            console.log("    IP              : " + this.options.ip)
            console.log("    Payload         : " + this.options.payload)
            console.log("    Session ID      : " + this.options.sessionId)
            console.log("    Start Time      : " + startTime)
            console.log("    Window(seconds) : " + this.options.windowSeconds)
            console.log("    End Time        : " + endTime)
            console.log("    Field Delimiter : " + this.options.fieldDelimiter)
            console.log("    ACL Delimiter   : " + this.options.aclDelimiter)
            console.log("    Escape Early    : " + this.options.escapeEarly)
        }

        var hashSource = []
        var newToken = []

        if (this.options.ip) {
            newToken.push("ip=" + this._escapeEarly(this.options.ip))
        }

        if (this.options.startTime) {
            newToken.push("st=" + startTime)
        }
        newToken.push("exp=" + endTime)

        if (!isUrl) {
            newToken.push("acl=" + path)
        }

        if (this.options.sessionId) {
            newToken.push("id=" + this._escapeEarly(this.options.sessionId))
        }

        if (this.options.payload) {
            newToken.push("data=" + this._escapeEarly(this.options.payload))
        }

        hashSource = newToken.slice()

        if (isUrl) {
            hashSource.push("url=" + this._escapeEarly(path))
        }

        if (this.options.salt) {
            hashSource.push("salt=" + this.options.salt)
        }

        this.options.algorithm = this.options.algorithm.toString().toLowerCase()
        if (!(this.options.algorithm == 'sha256' || this.options.algorithm == 'sha1' || this.options.algorithm == 'md5')) {
            throw new Error('altorithm should be sha256 or sha1 or md5')
        }

        var hmac = crypto.createHmac(
            this.options.algorithm,
            new Buffer(this.options.key, 'hex')
        )

        hmac.update(hashSource.join(this.options.fieldDelimiter))
        newToken.push("hmac=" + hmac.digest('hex'))

        return newToken.join(this.options.fieldDelimiter)
    }

    generateURLToken(url) {
        if (!url) {
            throw new Error('You must provide url')
        }
        return this._generateToken(url, true)
    }
}

function getViewerIp(request) {
    if(request.headers['cloudfront-viewer-address']){
        return request.headers['cloudfront-viewer-address'].substring(0, request.headers['cloudfront-viewer-address'].lastIndexOf(':'))
    } else {
        return request.clientIp;
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
    const keyId = queryStrings['kid'] ? queryStrings['kid']: 'KEY_ID';
    if(!KEYS[keyId]) {
        callback(null, Responses.with403('invalid key'));
        return;
    }
    const tokenName = "__token__";
    const windowSeconds = queryStrings["window"] ?queryStrings["window"]: "36000";
    const escapeEarly = "ESCAPE_EARLY";
    if(!KEYS[keyId]) {
        callback(null, Responses.with403('invalid key'));
        return;
    }
    let viewerDomain = 'VIEWER_DOMAIN_NAME';
    if(viewerDomain === "") {
        viewerDomain = event.Records[0].cf.config.distributionDomainName;
    }
    try {
        const edgeAuthOptions = {tokenName: tokenName, key: KEYS[keyId], windowSeconds: parseInt(windowSeconds), escapeEarly: escapeEarly}
        const tokenGenerator = new EdgeAuth(edgeAuthOptions);
        if(queryStrings[tokenName]) {
            const validationRes = tokenGenerator.validateToken(uri, queryStrings[tokenName])
            if(!validationRes.valid) {
                callback(null, Responses.with403('expired token'));
            }
            if(validationRes.ip !== "" && validationRes.ip !== getViewerIp(request)) {
                callback(null, Responses.with403('viewer ip not match'));
            }
            if(validationRes.id !== "") {
                edgeAuthOptions.sessionId = validationRes.id
            }
        }
        if(queryStrings["session"]) {
            edgeAuthOptions.sessionId = queryStrings["session"]
        }
        const token = tokenGenerator.generateURLToken(MASTER_MANIFESTS[manifestKey]);
        const playbackUrl = `https://${viewerDomain}${MASTER_MANIFESTS[manifestKey]}?${tokenName}=${token}&kid=${keyId}`
        callback(null, Responses.with201(playbackUrl));
    } catch(e) {
        callback(null, Responses.with403(e.message));
    }
};