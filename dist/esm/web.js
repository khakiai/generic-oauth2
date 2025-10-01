import { WebPlugin } from '@capacitor/core';
import { WebUtils } from './web-utils';
export class GenericOAuth2Web extends WebPlugin {
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
//# sourceMappingURL=web.js.map