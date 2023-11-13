var crypto = require('crypto'); // nosonar

//Response when JWT is not valid.
var response401 = { // nosonar
    statusCode: 401,
    statusDescription: 'Unauthorized'
};

var KEYS = 'TOKEN_KEYS';

function finalizeOptions(options) {
    if (!options.tokenName) {
        options.tokenName = '__token__'
    }

    if (!options.key) {
        throw new Error('key must be provided to generate a token.')
    }

    if (options.algorithm === undefined) {
        options.algorithm = 'sha256'
    }

    if (options.escapeEarly === undefined) {
        options.escapeEarly = false
    }

    if (!options.fieldDelimiter) {
        options.fieldDelimiter = '~'
    }

    if (!options.aclDelimiter) {
        options.aclDelimiter = '!'
    }

    if (options.verbose === undefined) {
       options.verbose = false
    }
    return options;
}
function _escapeEarly(text) {
    text = encodeURIComponent(text)
        .replace(/[~'*]/g,
            function(c) {
                return '%' + c.charCodeAt(0).toString(16)
            }
        )
    var pattern = /%../g
    return text.replace(pattern, function(match) {
        return match.toLowerCase()
    })
}
function validateToken(urlPath, token, options) {
    var tokenParts = token.split(options.fieldDelimiter);
    if(tokenParts.length < 2) {
        throw new Error('no hmac')
    }
    var hmacEntry = tokenParts.pop().split('=', 2);
    if(hmacEntry.length !== 2 && hmacEntry[0] !== 'hmac') {
        throw new Error('no hmac')
    }
    var hashSource = tokenParts.slice()
    hashSource.push("url=" + (options.escapeEarly ? _escapeEarly(urlPath) : urlPath))
    if (options.salt) {
        hashSource.push("salt=" + options.salt)
    }
    options.algorithm = options.algorithm.toString().toLowerCase()
    if (!(options.algorithm == 'sha256' || options.algorithm == 'sha1' || options.algorithm == 'md5')) {
        throw new Error('algorithm should be sha256 or sha1 or md5')
    }
    var hmac = crypto.createHmac(
        options.algorithm,
        String.bytesFrom(options.key, 'hex')
    )
    hmac.update(hashSource.join(options.fieldDelimiter))
    // var hmac = crypto.createHmac(options.algorithm, hexToString(options.key)).update(hashSource.join(options.fieldDelimiter))
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
    for (var i = 0; i < tokenParts.length; i++) {
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

function handler(event) {
    try{
        var request = event.request; // nosonar
        var queryStrings = request.querystring; // nosonar
        var viewerIp = event.viewer.ip; // nosonar
        var tokenName = "__token__";
        var windowSeconds = 300;
        var escapeEarly = "ESCAPE_EARLY";
        var keyId = queryStrings['kid'] ? queryStrings['kid'].value: 'KEY_ID';
        var edgeAuthOptions = {tokenName: tokenName, key: KEYS[keyId], windowSeconds: windowSeconds, escapeEarly: escapeEarly}
        if(!queryStrings[tokenName]) {
            return response401;
        }
        var token = queryStrings[tokenName].value
        var validationRes = validateToken(request.uri, token, finalizeOptions(edgeAuthOptions))
        if(!validationRes.valid) {
            return response401;
        }
        if(validationRes.ip !== "" && validationRes.ip !== viewerIp) {
            return response401;
        }
        delete request.querystring[tokenName];
        if(queryStrings['kid']) {
            delete request.querystring.kid;
        }
        return request;
    } catch(error){
        return response401;
    }

}

