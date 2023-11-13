'use strict';
const https = require('https');
const path = require('path');
const crypto = require("crypto");
const qs = require("querystring");
const AWS = require('aws-sdk');
const keepAliveAgent = new https.Agent({keepAlive: true});
https.globalAgent = keepAliveAgent;
var DDB_CLIENT = new AWS.DynamoDB({apiVersion: '2012-08-10', region: 'ap-southeast-1', httpOptions: {agent: keepAliveAgent}});
const KEYS = 'TOKEN_KEYS';
const TOKEN_TABLE = 'DDB_TABLE';
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
            Buffer.from(this.options.key, 'hex')
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
            hmac: actualHmacValue,
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
            throw new Error('algorithm should be sha256 or sha1 or md5')
        }

        var hmac = crypto.createHmac(
            this.options.algorithm,
            Buffer.from(this.options.key, 'hex')
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

    static with500(bodyStr) {
        return Responses.create('500', 'Internal Error', bodyStr)
    }
}

function getManifestContentLines(url) {
    return new Promise ((resolve, reject) => {
        let req =  https.get(url, (resp) => {
            let data = "";
            resp.on('data', (chunk) => {
                data += chunk;
            });
            const statusCode = resp.statusCode
            const headers = prepareResponseHeaders(resp)
            resp.on('end', () => {
                resolve({statusCode: statusCode, headers: headers, lines: data.split("\n")});
            });
        });
        req.on('error', err => {
            resolve({error: err});
        });
        req.end();
    });
}

function prepareResponseHeaders(resp) {
    let headers = {
        "content-type": [{"key": "Content-Type", "value": resp.headers["content-type"]||"text/html"}],
        "server": [{"key": "Server", "value": resp.headers["server"]||"Server"}]
    };
    const corsResponse = 'CORS_RESPONSE'
    if(corsResponse.length > 0) {
        headers['access-control-allow-origin'] = [{"key": "Access-Control-Allow-Origin", "value": corsResponse}]
    }
    return headers;
}

function rewriteManifest(lines, dir, tokenGenerator, tokenName, keyId) {
    let body = [];
    lines.forEach((elem)=> {
        if (elem.startsWith("#") ) {
            if(elem.indexOf("URI") !== -1) { //URI component inline
                var uriComponents = elem.substring(elem.indexOf("URI")).split("\"");
                var token = tokenGenerator.generateURLToken(path.posix.join(dir,uriComponents[1]));
                uriComponents[1] = uriComponents[1] + (uriComponents[1].indexOf("?") === -1 ? "?" : "&") + tokenName + "=" + token + "&kid=" + keyId  ;
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
            body.push(elem + (elem.indexOf("?") === -1 ? "?" : "&") + tokenName + "=" + tokenGenerator.generateURLToken(path.posix.join(dir, elem)) + "&kid=" + keyId );
        }
    });
    return body.join('\n');
}

function oneTimeAccessCheck(key) {
    return new Promise ((resolve, reject) => {
        DDB_CLIENT.getItem({
            Key: {
                'token': {S: key}
            },
            TableName: TOKEN_TABLE
        }, function(err, data) {
            if(err) {
                resolve(data); // just skip
                return;
            }
            if(data.Item) {
                reject(new Error('token already accessed'));
                return;
            }
            DDB_CLIENT.putItem({
                Item: {
                    'token': {S: key}
                },
                TableName: TOKEN_TABLE
            }, function(err, data) {
                resolve(data)
            })
        })
    })
}

function checkToken(tokenGenerator, uri, token, ip) {
    return new Promise ((resolve, reject) => {
        try {
            const validationRes = tokenGenerator.validateToken(uri, token)
            if(!validationRes.valid) {
                reject(new Error('expired token'));
                return;
            }
            if(validationRes.ip !== "" && validationRes.ip !== ip) {
                reject(new Error('viewer ip not match'));
            }
            resolve(validationRes)
        } catch(e) {
            reject(e)
        }
    })
}

exports.handler = async (event) => {
    const request = event.Records[0].cf.request;
    const queryStrings = qs.parse(request.querystring)
    const tokenName = "__token__";
    const windowSeconds = 300;
    const escapeEarly = "ESCAPE_EARLY";
    const keyId = queryStrings['kid'] ? queryStrings['kid']: 'KEY_ID';
    const manifestDomainUrl = 'https://MANIFEST_DOMAIN_NAME';
    let viewerDomain = 'VIEWER_DOMAIN_NAME';
    if(viewerDomain === "") {
        viewerDomain = event.Records[0].cf.config.distributionDomainName;
    }
    const edgeAuthOptions = {tokenName: tokenName, key: KEYS[keyId], windowSeconds: windowSeconds, escapeEarly: escapeEarly}
    const tokenGenerator = new EdgeAuth(edgeAuthOptions);
    const token = queryStrings[tokenName]
    if(!token) {
        return Responses.with403('no edge auth token');
    }
    try {
        delete queryStrings[tokenName]
        if(queryStrings['kid']) {
            delete queryStrings['kid']
        }
        let querystring = qs.stringify(queryStrings);
        let dir = path.dirname(request.uri);
        const promiseTokenCheck = checkToken(tokenGenerator, request.uri, token, getViewerIp(request))
        const promiseContent = getManifestContentLines(manifestDomainUrl+request.uri+querystring)
        const promiseGetOneTime = oneTimeAccessCheck(token)
        const [resp, oneTime, validationRes] = await Promise.all([promiseContent, promiseGetOneTime, promiseTokenCheck])
        if(resp.error) {
            return Responses.with500('failed to read content. ' + resp.error)
        }
        return {
            status: resp.statusCode,
            headers: resp.headers,
            body: rewriteManifest(resp.lines, dir, tokenGenerator, tokenName, keyId)
        };
    } catch(e) {
        return Responses.with403(e.message);
    }
};

