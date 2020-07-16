'use strict';

/**
 * HOW TO USE:
 * 
 * const createApiClient = require('876ex.js');
 * 
 * var client = createApiClient('your-api-key', 'your-api-secret', {
 *     host: 'api.876ex.com',
 *     https: true,
 *     timeout: 5,
 *     debug: true
 * });
 * 
 * client.get('/v1/users/wss/token', { k1: 'v1', k2: 'v2' }, function (err, resp) {
 *     if (err) {
 *         console.error('ERROR: ' + err);
 *     } else {
 *         console.log(resp)
 *     }
 * });
 * 
 * client.post('/v1/wallet/withdraw/addresses', { addressCurrency: 'BTC', address: '1BTCxxx', description: 'test' }, function (err, resp) {
 *     if (err) {
 *         console.error('ERROR: ' + err);
 *     } else {
 *         console.log(resp)
 *     }
 * });
 */
const
    http = require('http'),
    https = require('https'),
    crypto = require('crypto');

function ApiError(error, data, message) {
    this.error = error;
    this.data = data;
    this.message = message;
}

ApiError.prototype.name = 'ApiError';
ApiError.prototype.constructor = ApiError;
ApiError.prototype.toString = function () {
    return 'ApiError(' + this.error + ', data=' + this.data + ', message=' + this.message + ')';
};

/**
 * create API client.
 * 
 * @param {string} apiKey the api key.
 * @param {string} apiSecret the api secret.
 * @param {object} options options like { host: 'api.876ex.com', https: true, timeout: 5, debug: true }
 */
function createApiClient(apiKey, apiSecret, options) {
    var
        host = (options.host || 'api.876ex.com').toLowerCase(),
        protocol = options.https === false ? 'http' : 'https',
        timeout = options.timeout || 10,
        debug = options.debug || false;
    return new ApiClient(apiKey, apiSecret, host, protocol, timeout, debug);
}

function ApiClient(apiKey, apiSecret, host, protocol, timeout, debug) {
    var pos = host.indexOf(':');
    this.apiKey = apiKey;
    this.apiSecret = apiSecret;
    this.host = host;
    this.hostname = pos > 0 ? host.substring(0, pos) : host;
    this.port = pos > 0 ? host.substring(pos + 1) : (protocol === 'https' ? 443 : 80);
    this.protocol = protocol;
    this.timeout = timeout;
    this.debug = debug;
}

ApiClient.prototype.get = function (path, params, callback) {
    if (arguments.length === 2) {
        callback = params;
        params = null;
    }
    var
        k,
        ps = [];
    if (params) {
        for (k in params) {
            ps.push(k + '=' + params[k]);
        }
        ps.sort();
    }
    this._http('GET', path, ps.join('&'), '', callback);
}

ApiClient.prototype.post = function (path, data, callback) {
    if (arguments.length === 2) {
        callback = data;
        data = {};
    }
    this._http('POST', path, '', JSON.stringify(data || {}), callback);
}

ApiClient.prototype._http = function (method, path, params, data, callback) {
    var
        payload, str, sign, req, k, url,
        ts = Date.now(),
        lines = [method, this.hostname, path, params],
        headers = {
            'API-KEY': this.apiKey,
            'API-SIGNATURE-METHOD': 'HmacSHA256',
            'API-SIGNATURE-VERSION': '1',
            'API-TIMESTAMP': '' + ts,
            'API-UNIQUE-ID': 'uk' + ts
        },
        headerLines = [];
    for (k in headers) {
        headerLines.push(k + ': ' + headers[k]);
    }
    headerLines.sort();
    payload = lines.concat(headerLines);
    payload.push(data ? data : '')
    console.log(JSON.stringify(payload))
    str = payload.join('\n');
    sign = crypto.createHmac('sha256', this.apiSecret).update(str).digest('hex');
    if (this.debug) {
        console.log('payload:\n----\n' + str + '----\nsignature: ' + sign);
    }
    // build request:
    headers['API-SIGNATURE'] = sign;
    if (method === 'GET' && params) {
        path = path + '?' + params;
    }
    if (method === 'POST') {
        headers['Content-Type'] = 'application/json';
    }
    url = this.protocol + '://' + this.host + path;
    req = (this.protocol === 'https' ? https : http).request({
        host: this.hostname,
        port: this.port,
        method: method,
        path: path,
        headers: headers,
    }, function (res) {
        res.on('data', function (data) {
            var result = JSON.parse(data.toString('utf8'));
            if (result.error) {
                callback(new ApiError(result.error, result.data, result.message));
            } else {
                callback(null, result);
            }
        });
    });
    if (method === 'POST') {
        req.write(data);
    }
    req.end();
}

if (process && process.version) {
    // nodejs
    module.exports = createApiClient;
}
