'use strict';

var core = require('@capacitor/core');

const GenericOAuth2 = core.registerPlugin('GenericOAuth2', {
    web: () => Promise.resolve().then(function () { return web; }).then(m => new m.GenericOAuth2Web()),
});

// import sha256 from "fast-sha256";
class WebUtils {
    /**
     * Public only for testing
     */
    static getAppId(options) {
        return this.getOverwritableValue(options, 'appId');
    }
    static getOverwritableValue(options, key) {
        let base = options[key];
        if (options.web && key in options.web) {
            base = options.web[key];
        }
        return base;
    }
    /**
     * Public only for testing
     */
    static getAuthorizationUrl(options) {
        let url = options.authorizationBaseUrl + '?client_id=' + options.appId;
        url += '&response_type=' + options.responseType;
        if (options.redirectUrl) {
            url += '&redirect_uri=' + options.redirectUrl;
        }
        if (options.scope) {
            url += '&scope=' + options.scope;
        }
        url += '&state=' + options.state;
        if (options.additionalParameters) {
            for (const key in options.additionalParameters) {
                url += '&' + key + '=' + options.additionalParameters[key];
            }
        }
        if (options.pkceCodeChallenge) {
            url += '&code_challenge=' + options.pkceCodeChallenge;
            url += '&code_challenge_method=' + options.pkceCodeChallengeMethod;
        }
        return encodeURI(url);
    }
    static getTokenEndpointData(options, code) {
        let body = '';
        body +=
            encodeURIComponent('grant_type') +
                '=' +
                encodeURIComponent('authorization_code') +
                '&';
        body +=
            encodeURIComponent('client_id') +
                '=' +
                encodeURIComponent(options.appId) +
                '&';
        body +=
            encodeURIComponent('redirect_uri') +
                '=' +
                encodeURIComponent(options.redirectUrl) +
                '&';
        body += encodeURIComponent('code') + '=' + encodeURIComponent(code) + '&';
        body +=
            encodeURIComponent('code_verifier') +
                '=' +
                encodeURIComponent(options.pkceCodeVerifier);
        return body;
    }
    static setCodeVerifier(code) {
        try {
            window.sessionStorage.setItem(`I_Capacitor_GenericOAuth2Plugin_PKCE`, code);
            return true;
        }
        catch (err) {
            return false;
        }
    }
    static clearCodeVerifier() {
        window.sessionStorage.removeItem(`I_Capacitor_GenericOAuth2Plugin_PKCE`);
    }
    static getCodeVerifier() {
        return window.sessionStorage.getItem(`I_Capacitor_GenericOAuth2Plugin_PKCE`);
    }
    /**
     * Public only for testing
     */
    static getUrlParams(url) {
        const urlString = `${url !== null && url !== void 0 ? url : ''}`.trim();
        if (urlString.length === 0) {
            return;
        }
        const parsedUrl = new URL(urlString);
        if (!parsedUrl.search && !parsedUrl.hash) {
            return;
        }
        let urlParamStr;
        if (parsedUrl.search) {
            urlParamStr = parsedUrl.search.substr(1);
        }
        else {
            urlParamStr = parsedUrl.hash.substr(1);
        }
        const keyValuePairs = urlParamStr.split(`&`);
        return keyValuePairs.reduce((accumulator, currentValue) => {
            const [key, val] = currentValue.split(`=`);
            if (key && key.length > 0) {
                return Object.assign(Object.assign({}, accumulator), { [key]: decodeURIComponent(val) });
            }
        }, {});
    }
    static randomString(length = 10) {
        const haystack = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';
        let randomStr;
        if (window.crypto) {
            let numberArray = new Uint32Array(length);
            window.crypto.getRandomValues(numberArray);
            numberArray = numberArray.map(x => haystack.charCodeAt(x % haystack.length));
            const stringArray = [];
            numberArray.forEach(x => {
                stringArray.push(haystack.charAt(x % haystack.length));
            });
            randomStr = stringArray.join('');
        }
        else {
            randomStr = '';
            for (let i = 0; i < length; i++) {
                randomStr += haystack.charAt(Math.floor(Math.random() * haystack.length));
            }
        }
        return randomStr;
    }
    static async buildWebOptions(configOptions) {
        var _a;
        const webOptions = new WebOptions();
        webOptions.appId = this.getAppId(configOptions);
        webOptions.authorizationBaseUrl = this.getOverwritableValue(configOptions, 'authorizationBaseUrl');
        webOptions.responseType = this.getOverwritableValue(configOptions, 'responseType');
        if (!webOptions.responseType) {
            webOptions.responseType = 'token';
        }
        webOptions.redirectUrl = this.getOverwritableValue(configOptions, 'redirectUrl');
        // controlling parameters
        webOptions.resourceUrl = this.getOverwritableValue(configOptions, 'resourceUrl');
        webOptions.accessTokenEndpoint = this.getOverwritableValue(configOptions, 'accessTokenEndpoint');
        webOptions.pkceEnabled = this.getOverwritableValue(configOptions, 'pkceEnabled');
        webOptions.sendCacheControlHeader =
            (_a = this.getOverwritableValue(configOptions, 'sendCacheControlHeader')) !== null && _a !== void 0 ? _a : webOptions.sendCacheControlHeader;
        if (webOptions.pkceEnabled) {
            const pkceCode = this.getCodeVerifier();
            if (pkceCode) {
                webOptions.pkceCodeVerifier = pkceCode;
            }
            else {
                webOptions.pkceCodeVerifier = this.randomString(64);
                this.setCodeVerifier(webOptions.pkceCodeVerifier);
            }
            if (CryptoUtils.HAS_SUBTLE_CRYPTO) {
                await CryptoUtils.deriveChallenge(webOptions.pkceCodeVerifier).then(c => {
                    webOptions.pkceCodeChallenge = c;
                    webOptions.pkceCodeChallengeMethod = 'S256';
                });
            }
            else {
                webOptions.pkceCodeChallenge = webOptions.pkceCodeVerifier;
                webOptions.pkceCodeChallengeMethod = 'plain';
            }
        }
        webOptions.scope = this.getOverwritableValue(configOptions, 'scope');
        webOptions.state = this.getOverwritableValue(configOptions, 'state');
        if (!webOptions.state || webOptions.state.length === 0) {
            webOptions.state = this.randomString(20);
        }
        const parametersMapHelper = this.getOverwritableValue(configOptions, 'additionalParameters');
        if (parametersMapHelper) {
            webOptions.additionalParameters = {};
            for (const key in parametersMapHelper) {
                if (key && key.trim().length > 0) {
                    const value = parametersMapHelper[key];
                    if (value && value.trim().length > 0) {
                        webOptions.additionalParameters[key] = value;
                    }
                }
            }
        }
        const headersMapHelper = this.getOverwritableValue(configOptions, 'additionalResourceHeaders');
        if (headersMapHelper) {
            webOptions.additionalResourceHeaders = {};
            for (const key in headersMapHelper) {
                if (key && key.trim().length > 0) {
                    const value = headersMapHelper[key];
                    if (value && value.trim().length > 0) {
                        webOptions.additionalResourceHeaders[key] = value;
                    }
                }
            }
        }
        webOptions.logsEnabled = this.getOverwritableValue(configOptions, 'logsEnabled');
        return webOptions;
    }
    static buildWindowOptions(configOptions) {
        const windowOptions = new WebOptions();
        if (configOptions.web) {
            if (configOptions.web.windowOptions) {
                windowOptions.windowOptions = configOptions.web.windowOptions;
            }
            if (configOptions.web.windowTarget) {
                windowOptions.windowTarget = configOptions.web.windowTarget;
            }
        }
        return windowOptions;
    }
}
class CryptoUtils {
    static toUint8Array(str) {
        const buf = new ArrayBuffer(str.length);
        const bufView = new Uint8Array(buf);
        for (let i = 0; i < str.length; i++) {
            bufView[i] = str.charCodeAt(i);
        }
        return bufView;
    }
    static toBase64Url(base64) {
        return base64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
    }
    static toBase64(bytes) {
        const len = bytes.length;
        let base64 = '';
        for (let i = 0; i < len; i += 3) {
            base64 += this.BASE64_CHARS[bytes[i] >> 2];
            base64 += this.BASE64_CHARS[((bytes[i] & 3) << 4) | (bytes[i + 1] >> 4)];
            base64 +=
                this.BASE64_CHARS[((bytes[i + 1] & 15) << 2) | (bytes[i + 2] >> 6)];
            base64 += this.BASE64_CHARS[bytes[i + 2] & 63];
        }
        if (len % 3 === 2) {
            base64 = base64.substring(0, base64.length - 1) + '=';
        }
        else if (len % 3 === 1) {
            base64 = base64.substring(0, base64.length - 2) + '==';
        }
        return base64;
    }
    static deriveChallenge(codeVerifier) {
        if (codeVerifier.length < 43 || codeVerifier.length > 128) {
            return Promise.reject(new Error('ERR_PKCE_CODE_VERIFIER_INVALID_LENGTH'));
        }
        if (!CryptoUtils.HAS_SUBTLE_CRYPTO) {
            return Promise.reject(new Error('ERR_PKCE_CRYPTO_NOTSUPPORTED'));
        }
        return new Promise((resolve, reject) => {
            crypto.subtle.digest('SHA-256', this.toUint8Array(codeVerifier)).then(arrayBuffer => {
                return resolve(this.toBase64Url(this.toBase64(new Uint8Array(arrayBuffer))));
            }, error => reject(error));
        });
    }
}
CryptoUtils.BASE64_CHARS = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
CryptoUtils.HAS_SUBTLE_CRYPTO = typeof window !== 'undefined' &&
    !!window.crypto &&
    !!window.crypto.subtle;
class WebOptions {
    constructor() {
        this.sendCacheControlHeader = true;
        this.windowTarget = '_blank';
    }
}

class GenericOAuth2Web extends core.WebPlugin {
    constructor() {
        super(...arguments);
        this.windowHandle = null;
        this.intervalId = null;
        this.loopCount = 2000;
        this.intervalLength = 100;
        this.windowClosedByPlugin = false;
        this.MSG_RETURNED_TO_JS = 'Returned to JS:';
    }
    /**
     * Get a new access token using an existing refresh token.
     */
    // eslint-disable-next-line @typescript-eslint/no-unused-vars
    async refreshToken(_options) {
        return new Promise((_resolve, reject) => {
            reject(new Error('Functionality not implemented for PWAs yet'));
        });
    }
    /**
     * New: Pure redirect consumer. No popup/window required.
     * Call this from your /auth/callback route with the full redirected URL.
     * Returns the same payload shape produced by requestResource/assignResponses.
     */
    async consumeRedirectUrl(redirectedUrl, options) {
        const webOptions = options.authorizationBaseUrl && options.redirectUrl
            ? options
            : await WebUtils.buildWebOptions(options);
        const urlParams = WebUtils.getUrlParams(redirectedUrl);
        if (!urlParams) {
            throw new Error('Oauth Parameters where not present in url.');
        }
        if (webOptions.logsEnabled) {
            this.doLog('Authorization response (pure):', urlParams);
        }
        // State check (CSRF)
        if (urlParams.state !== webOptions.state) {
            if (webOptions.logsEnabled) {
                this.doLog('State from web options: ' + webOptions.state);
                this.doLog('State returned from provider: ' + urlParams.state);
            }
            throw new Error('ERR_STATES_NOT_MATCH');
        }
        // Authorization Code (+PKCE) flow
        if (webOptions.accessTokenEndpoint) {
            const authorizationCode = urlParams.code;
            if (!authorizationCode)
                throw new Error('ERR_NO_AUTHORIZATION_CODE');
            const form = new URLSearchParams(WebUtils.getTokenEndpointData(webOptions, authorizationCode));
            const headers = {
                accept: 'application/json',
                'content-type': 'application/x-www-form-urlencoded',
            };
            if (webOptions.sendCacheControlHeader)
                headers['cache-control'] = 'no-cache';
            let accessTokenResponse;
            try {
                const resp = await fetch(webOptions.accessTokenEndpoint, {
                    method: 'POST',
                    headers,
                    body: form,
                });
                if (!resp.ok)
                    throw new Error(`ERR_GENERAL`);
                accessTokenResponse = await resp.json();
                WebUtils.clearCodeVerifier();
            }
            catch (_e) {
                this.doLog('ERR_GENERAL during token exchange');
                throw new Error('ERR_GENERAL');
            }
            if (webOptions.logsEnabled)
                this.doLog('Access token response (pure):', accessTokenResponse);
            if (webOptions.resourceUrl) {
                const resource = await this.fetchResourcePure(webOptions, accessTokenResponse.access_token);
                const result = {};
                this.assignResponses(result, accessTokenResponse.access_token, urlParams, accessTokenResponse);
                Object.assign(result, resource);
                if (webOptions.logsEnabled)
                    this.doLog(this.MSG_RETURNED_TO_JS, result);
                return result;
            }
            else {
                const result = {};
                this.assignResponses(result, accessTokenResponse.access_token, urlParams, accessTokenResponse);
                if (webOptions.logsEnabled)
                    this.doLog(this.MSG_RETURNED_TO_JS, result);
                return result;
            }
        }
        // Implicit flow
        const accessToken = urlParams.access_token;
        if (!accessToken) {
            throw new Error('ERR_NO_ACCESS_TOKEN');
        }
        if (webOptions.resourceUrl) {
            const resource = await this.fetchResourcePure(webOptions, accessToken);
            const result = {};
            this.assignResponses(result, accessToken, urlParams, null);
            Object.assign(result, resource);
            if (webOptions.logsEnabled)
                this.doLog(this.MSG_RETURNED_TO_JS, result);
            return result;
        }
        else {
            const result = {};
            this.assignResponses(result, accessToken, urlParams, null);
            if (webOptions.logsEnabled)
                this.doLog(this.MSG_RETURNED_TO_JS, result);
            return result;
        }
    }
    async redirectFlowCodeListener(options) {
        this.webOptions = await WebUtils.buildWebOptions(options);
        return new Promise((resolve, reject) => {
            const urlParamObj = WebUtils.getUrlParams(options.response_url);
            if (urlParamObj) {
                const code = urlParamObj.code;
                if (code) {
                    this.getAccessToken(urlParamObj, resolve, reject, code);
                }
                else {
                    reject(new Error('Oauth Code parameter was not present in url.'));
                }
            }
            else {
                reject(new Error('Oauth Parameters where not present in url.'));
            }
        });
    }
    async authenticate(options) {
        return this.syncAuthenticate(options);
    }
    syncAuthenticate(options) {
        const windowOptions = WebUtils.buildWindowOptions(options);
        // open placeholder window first to avoid popup blockers
        this.windowHandle =
            options.windowHandle || window.open('', windowOptions.windowTarget, windowOptions.windowOptions);
        return WebUtils.buildWebOptions(options).then((webOptions) => {
            this.webOptions = webOptions;
            return new Promise((resolve, reject) => {
                // validate
                if (!this.webOptions.appId || this.webOptions.appId.length === 0) {
                    reject(new Error('ERR_PARAM_NO_APP_ID'));
                    return;
                }
                else if (!this.webOptions.authorizationBaseUrl || this.webOptions.authorizationBaseUrl.length === 0) {
                    reject(new Error('ERR_PARAM_NO_AUTHORIZATION_BASE_URL'));
                    return;
                }
                else if (!this.webOptions.redirectUrl || this.webOptions.redirectUrl.length === 0) {
                    reject(new Error('ERR_PARAM_NO_REDIRECT_URL'));
                    return;
                }
                else if (!this.webOptions.responseType || this.webOptions.responseType.length === 0) {
                    reject(new Error('ERR_PARAM_NO_RESPONSE_TYPE'));
                    return;
                }
                // init internal control params
                let loopCount = this.loopCount;
                this.windowClosedByPlugin = false;
                // open window with the authorization URL
                const authorizationUrl = WebUtils.getAuthorizationUrl(this.webOptions);
                if (this.webOptions.logsEnabled) {
                    this.doLog('Authorization url: ' + authorizationUrl);
                }
                if (this.windowHandle) {
                    this.windowHandle.location.href = authorizationUrl;
                }
                // polling loop for redirect / closure (same-origin only)
                this.intervalId = window.setInterval(() => {
                    var _a;
                    if (loopCount-- < 0) {
                        this.closeWindow();
                    }
                    else if (((_a = this.windowHandle) === null || _a === void 0 ? void 0 : _a.closed) && !this.windowClosedByPlugin) {
                        window.clearInterval(this.intervalId);
                        reject(new Error('USER_CANCELLED'));
                    }
                    else {
                        let href;
                        try {
                            href = this.windowHandle.location.href;
                        }
                        catch (_ignore) {
                            // cross-origin; ignore DOMException
                        }
                        if (href != null && href.indexOf(this.webOptions.redirectUrl) >= 0) {
                            if (this.webOptions.logsEnabled) {
                                this.doLog('Url from Provider: ' + href);
                            }
                            const authorizationRedirectUrlParamObj = WebUtils.getUrlParams(href);
                            if (authorizationRedirectUrlParamObj) {
                                if (this.webOptions.logsEnabled) {
                                    this.doLog('Authorization response:', authorizationRedirectUrlParamObj);
                                }
                                window.clearInterval(this.intervalId);
                                // state check
                                if (authorizationRedirectUrlParamObj.state === this.webOptions.state) {
                                    if (this.webOptions.accessTokenEndpoint) {
                                        const authorizationCode = authorizationRedirectUrlParamObj.code;
                                        if (authorizationCode) {
                                            this.getAccessToken(authorizationRedirectUrlParamObj, resolve, reject, authorizationCode);
                                        }
                                        else {
                                            reject(new Error('ERR_NO_AUTHORIZATION_CODE'));
                                        }
                                        this.closeWindow();
                                    }
                                    else {
                                        // implicit flow: request resource or resolve immediately
                                        this.requestResource(authorizationRedirectUrlParamObj.access_token, resolve, reject, authorizationRedirectUrlParamObj);
                                    }
                                }
                                else {
                                    if (this.webOptions.logsEnabled) {
                                        this.doLog('State from web options: ' + this.webOptions.state);
                                        this.doLog('State returned from provider: ' + authorizationRedirectUrlParamObj.state);
                                    }
                                    reject(new Error('ERR_STATES_NOT_MATCH'));
                                    this.closeWindow();
                                }
                            }
                            // no else: continue polling if not our redirect
                        }
                    }
                }, this.intervalLength);
            });
        });
    }
    getAccessToken(authorizationRedirectUrlParamObj, resolve, reject, authorizationCode) {
        const tokenRequest = new XMLHttpRequest();
        tokenRequest.onload = () => {
            WebUtils.clearCodeVerifier();
            if (tokenRequest.status === 200) {
                const accessTokenResponse = JSON.parse(tokenRequest.response);
                if (this.webOptions.logsEnabled) {
                    this.doLog('Access token response:', accessTokenResponse);
                }
                this.requestResource(accessTokenResponse.access_token, resolve, reject, authorizationRedirectUrlParamObj, accessTokenResponse);
            }
            else {
                this.doLog('ERR_GENERAL: Token endpoint HTTP ' + tokenRequest.status);
                reject(new Error('ERR_GENERAL'));
            }
        };
        tokenRequest.onerror = () => {
            this.doLog('ERR_GENERAL: See client logs. It might be CORS. Status text: ' + tokenRequest.statusText);
            reject(new Error('ERR_GENERAL'));
        };
        tokenRequest.open('POST', this.webOptions.accessTokenEndpoint, true);
        tokenRequest.setRequestHeader('accept', 'application/json');
        if (this.webOptions.sendCacheControlHeader) {
            tokenRequest.setRequestHeader('cache-control', 'no-cache');
        }
        tokenRequest.setRequestHeader('content-type', 'application/x-www-form-urlencoded');
        tokenRequest.send(WebUtils.getTokenEndpointData(this.webOptions, authorizationCode));
    }
    requestResource(accessToken, resolve, reject, authorizationResponse, accessTokenResponse = null) {
        if (this.webOptions.resourceUrl) {
            const logsEnabled = this.webOptions.logsEnabled;
            if (logsEnabled) {
                this.doLog('Resource url: ' + this.webOptions.resourceUrl);
            }
            if (accessToken) {
                if (logsEnabled) {
                    this.doLog('Access token:', accessToken);
                }
                const self = this;
                const request = new XMLHttpRequest();
                request.onload = function () {
                    if (this.status === 200) {
                        const resp = JSON.parse(this.response);
                        if (logsEnabled) {
                            self.doLog('Resource response:', resp);
                        }
                        if (resp) {
                            self.assignResponses(resp, accessToken, authorizationResponse, accessTokenResponse);
                        }
                        if (logsEnabled) {
                            self.doLog(self.MSG_RETURNED_TO_JS, resp);
                        }
                        resolve(resp);
                    }
                    else {
                        reject(new Error(this.statusText));
                    }
                    self.closeWindow();
                };
                request.onerror = function () {
                    if (logsEnabled) {
                        self.doLog('ERR_GENERAL: ' + this.statusText);
                    }
                    reject(new Error('ERR_GENERAL'));
                    self.closeWindow();
                };
                request.open('GET', this.webOptions.resourceUrl, true);
                request.setRequestHeader('Authorization', `Bearer ${accessToken}`);
                if (this.webOptions.additionalResourceHeaders) {
                    for (const key in this.webOptions.additionalResourceHeaders) {
                        request.setRequestHeader(key, this.webOptions.additionalResourceHeaders[key]);
                    }
                }
                request.send();
            }
            else {
                if (logsEnabled) {
                    this.doLog('No accessToken was provided although you configured a resourceUrl. Remove the resourceUrl from the config.');
                }
                reject(new Error('ERR_NO_ACCESS_TOKEN'));
                this.closeWindow();
            }
        }
        else {
            // if no resource url exists just return the accessToken response
            const resp = {};
            this.assignResponses(resp, accessToken, authorizationResponse, accessTokenResponse);
            if (this.webOptions.logsEnabled) {
                this.doLog(this.MSG_RETURNED_TO_JS, resp);
            }
            resolve(resp);
            this.closeWindow();
        }
    }
    async fetchResourcePure(webOptions, accessToken) {
        if (!webOptions.resourceUrl)
            return {};
        const headers = { Authorization: `Bearer ${accessToken}` };
        if (webOptions.additionalResourceHeaders) {
            for (const k in webOptions.additionalResourceHeaders) {
                headers[k] = webOptions.additionalResourceHeaders[k];
            }
        }
        try {
            const resp = await fetch(webOptions.resourceUrl, { headers });
            if (!resp.ok)
                throw new Error(resp.statusText);
            const json = await resp.json();
            if (webOptions.logsEnabled)
                this.doLog('Resource response (pure):', json);
            return json !== null && json !== void 0 ? json : {};
        }
        catch (e) {
            if (webOptions.logsEnabled)
                this.doLog('ERR_GENERAL (resource): ' + (e === null || e === void 0 ? void 0 : e.message));
            throw new Error((e === null || e === void 0 ? void 0 : e.message) || 'ERR_GENERAL');
        }
    }
    assignResponses(resp, accessToken, authorizationResponse, accessTokenResponse = null) {
        // #154
        if (authorizationResponse) {
            resp['authorization_response'] = authorizationResponse;
        }
        if (accessTokenResponse) {
            resp['access_token_response'] = accessTokenResponse;
        }
        resp['access_token'] = accessToken;
    }
    async logout(options) {
        return new Promise((resolve, _reject) => {
            localStorage.removeItem(WebUtils.getAppId(options));
            resolve(true);
        });
    }
    closeWindow() {
        var _a;
        if (this.intervalId !== null) {
            window.clearInterval(this.intervalId);
            this.intervalId = null;
        }
        // #164 if the provider's login page is opened in the same tab or window it must not be closed
        // if (this.webOptions.windowTarget !== "_self") {
        //     this.windowHandle?.close();
        // }
        (_a = this.windowHandle) === null || _a === void 0 ? void 0 : _a.close();
        this.windowClosedByPlugin = true;
    }
    doLog(msg, obj = null) {
        // eslint-disable-next-line no-console
        console.log('I/Capacitor/GenericOAuth2Plugin: ' + msg, obj);
    }
}

var web = /*#__PURE__*/Object.freeze({
    __proto__: null,
    GenericOAuth2Web: GenericOAuth2Web
});

exports.GenericOAuth2 = GenericOAuth2;
//# sourceMappingURL=plugin.cjs.js.map
