import { WebPlugin } from '@capacitor/core';

import type {
  OAuth2AuthenticateOptions,
  GenericOAuth2Plugin,
  OAuth2RefreshTokenOptions,
  ImplicitFlowRedirectOptions,
} from './definitions';
import type { WebOptions } from './web-utils';
import { WebUtils } from './web-utils';

export class GenericOAuth2Web extends WebPlugin implements GenericOAuth2Plugin {
  private webOptions: WebOptions;
  private windowHandle: Window | null;
  private intervalId: number;
  private loopCount = 2000;
  private intervalLength = 100;
  private windowClosedByPlugin: boolean;

  private storageListenAbort?: () => void;

  private storageKey(state: string): string {
    const prefix = this.webOptions?.callbackStoragePrefix ?? 'oauth2';
    return `${prefix}:${state}`;
  }

  private waitForCallbackViaStorage(state: string, timeoutMs = 120_000): Promise<string> {
    return new Promise((resolve, reject) => {
      const key = this.storageKey(state);
      const existing = localStorage.getItem(key);
      if (existing) {
        localStorage.removeItem(key);
        return resolve(existing);
      }
      console.log(`I/Capacitor/GenericOAuth2Plugin: Listening for storage key ${key}`);

      const onStorage = (e: StorageEvent) => {
        if (e.key === key && typeof e.newValue === 'string') {
          try {
            resolve(e.newValue);
          } finally {
            localStorage.removeItem(key);
            window.removeEventListener('storage', onStorage);
            if (this.storageListenAbort) this.storageListenAbort = undefined;
          }
        }
      };

      window.addEventListener('storage', onStorage);
      this.storageListenAbort = () => {
        window.removeEventListener('storage', onStorage);
        this.storageListenAbort = undefined;
      };

      const t = window.setTimeout(() => {
        window.removeEventListener('storage', onStorage);
        this.storageListenAbort = undefined;
        reject(new Error('TIMEOUT'));
      }, timeoutMs);

      // ensure the timeout gets cleared when resolve runs
      const origResolve: (value: string | PromiseLike<string>) => void = resolve;
      resolve = (v: string | PromiseLike<string>) => {
        window.clearTimeout(t);
        origResolve(v);
      };
    });
  }

  /**
   * Get a new access token using an existing refresh token.
   */
  // eslint-disable-next-line @typescript-eslint/no-unused-vars
  async refreshToken(_options: OAuth2RefreshTokenOptions): Promise<any> {
    return new Promise<any>((_resolve, reject) => {
      reject(new Error('Functionality not implemented for PWAs yet'));
    });
  }

  async redirectFlowCodeListener(options: ImplicitFlowRedirectOptions): Promise<any> {
    this.webOptions = await WebUtils.buildWebOptions(options);
    return new Promise((resolve, reject) => {
      const urlParamObj = WebUtils.getUrlParams(options.response_url);
      if (urlParamObj) {
        const code = urlParamObj.code;
        if (code) {
          this.getAccessToken(urlParamObj, resolve, reject, code);
        } else {
          reject(new Error('Oauth Code parameter was not present in url.'));
        }
      } else {
        reject(new Error('Oauth Parameters where not present in url.'));
      }
    });
  }

  async authenticate(options: OAuth2AuthenticateOptions): Promise<any> {
    return this.syncAuthenticate(options);
  }

  syncAuthenticate(options: OAuth2AuthenticateOptions): Promise<any> {
    const windowOptions = WebUtils.buildWindowOptions(options);

    // open synchronously to avoid popup blockers
    this.windowHandle =
      options.windowHandle || window.open('', windowOptions.windowTarget, windowOptions.windowOptions);

    return WebUtils.buildWebOptions(options).then((webOptions) => {
      this.webOptions = webOptions;
      return new Promise<any>((resolve, reject) => {
        // validate
        if (!this.webOptions.appId || this.webOptions.appId.length == 0) {
          reject(new Error('ERR_PARAM_NO_APP_ID'));
          return;
        } else if (!this.webOptions.authorizationBaseUrl || this.webOptions.authorizationBaseUrl.length == 0) {
          reject(new Error('ERR_PARAM_NO_AUTHORIZATION_BASE_URL'));
          return;
        } else if (!this.webOptions.redirectUrl || this.webOptions.redirectUrl.length == 0) {
          reject(new Error('ERR_PARAM_NO_REDIRECT_URL'));
          return;
        } else if (!this.webOptions.responseType || this.webOptions.responseType.length == 0) {
          reject(new Error('ERR_PARAM_NO_RESPONSE_TYPE'));
          return;
        }

        // control params
        let loopCount = this.loopCount;
        this.windowClosedByPlugin = false;

        // open window
        const authorizationUrl = WebUtils.getAuthorizationUrl(this.webOptions);
        if (this.webOptions.logsEnabled) this.doLog('Authorization url: ' + authorizationUrl);
        if (this.windowHandle) this.windowHandle.location.href = authorizationUrl;

        // === COOP path: wait via localStorage; do NOT treat popup close as error ===
        if (this.webOptions.coop) {
          const timeoutMs = (this.webOptions as any).coopTimeoutMs ?? 120_000;
          this.waitForCallbackViaStorage(this.webOptions.state, timeoutMs)
            .then((href) => {
              if (this.webOptions.logsEnabled) this.doLog('Url from Provider (storage): ' + href);
              const params = WebUtils.getUrlParams(href);
              if (!params) {
                this.closeWindow();
                return reject(new Error('ERR_NO_URL_PARAMS'));
              }
              if (this.webOptions.logsEnabled) this.doLog('Authorization response:', params);

              if (params.state !== this.webOptions.state) {
                if (this.webOptions.logsEnabled) {
                  this.doLog('State from web options: ' + this.webOptions.state);
                  this.doLog('State returned from provider: ' + params.state);
                }
                this.closeWindow();
                return reject(new Error('ERR_STATES_NOT_MATCH'));
              }

              if (this.webOptions.accessTokenEndpoint) {
                const code = params.code;
                if (!code) {
                  this.closeWindow();
                  return reject(new Error('ERR_NO_AUTHORIZATION_CODE'));
                }
                this.getAccessToken(params, resolve, reject, code);
                this.closeWindow();
              } else {
                this.requestResource(params.access_token, resolve, reject, params);
                // requestResource closes window
              }
            })
            .catch((e) => {
              // Under COOP, we only surface TIMEOUT/GENERIC; user-closing the popup is not explicitly treated as error
              reject(e);
              this.closeWindow();
            });
          return; // IMPORTANT: skip legacy polling
        }

        // === Non-COOP path: original polling approach ===
        this.intervalId = window.setInterval(() => {
          if (loopCount-- < 0) {
            this.closeWindow();
          } else if (this.windowHandle?.closed && !this.windowClosedByPlugin) {
            window.clearInterval(this.intervalId);
            reject(new Error('USER_CANCELLED'));
          } else {
            // eslint-disable-next-line @typescript-eslint/no-non-null-assertion
            let href: string = undefined!;
            try {
              // eslint-disable-next-line @typescript-eslint/no-non-null-assertion
              href = this.windowHandle!.location.href!;
            } catch {
              // ignore cross-origin access
            }

            if (href != null && href.indexOf(this.webOptions.redirectUrl) >= 0) {
              if (this.webOptions.logsEnabled) this.doLog('Url from Provider: ' + href);
              const authorizationRedirectUrlParamObj = WebUtils.getUrlParams(href);
              if (authorizationRedirectUrlParamObj) {
                if (this.webOptions.logsEnabled)
                  this.doLog('Authorization response:', authorizationRedirectUrlParamObj);
                window.clearInterval(this.intervalId);
                if (authorizationRedirectUrlParamObj.state === this.webOptions.state) {
                  if (this.webOptions.accessTokenEndpoint) {
                    const authorizationCode = authorizationRedirectUrlParamObj.code;
                    if (authorizationCode) {
                      this.getAccessToken(authorizationRedirectUrlParamObj, resolve, reject, authorizationCode);
                    } else {
                      reject(new Error('ERR_NO_AUTHORIZATION_CODE'));
                    }
                    this.closeWindow();
                  } else {
                    this.requestResource(
                      authorizationRedirectUrlParamObj.access_token,
                      resolve,
                      reject,
                      authorizationRedirectUrlParamObj,
                    );
                  }
                } else {
                  if (this.webOptions.logsEnabled) {
                    this.doLog('State from web options: ' + this.webOptions.state);
                    this.doLog('State returned from provider: ' + authorizationRedirectUrlParamObj.state);
                  }
                  reject(new Error('ERR_STATES_NOT_MATCH'));
                  this.closeWindow();
                }
              }
            }
          }
        }, this.intervalLength);
      });
    });
  }

  private readonly MSG_RETURNED_TO_JS = 'Returned to JS:';

  private getAccessToken(
    authorizationRedirectUrlParamObj: { [p: string]: string } | undefined,
    resolve: (value: any) => void,
    reject: (reason?: any) => void,
    authorizationCode: string,
  ) {
    const tokenRequest = new XMLHttpRequest();
    tokenRequest.onload = () => {
      WebUtils.clearCodeVerifier();
      if (tokenRequest.status === 200) {
        const accessTokenResponse = JSON.parse(tokenRequest.response);
        if (this.webOptions.logsEnabled) this.doLog('Access token response:', accessTokenResponse);
        this.requestResource(
          accessTokenResponse.access_token,
          resolve,
          reject,
          authorizationRedirectUrlParamObj,
          accessTokenResponse,
        );
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

  private requestResource(
    accessToken: string,
    resolve: any,
    reject: (reason?: any) => void,
    authorizationResponse: any,
    accessTokenResponse: any = null,
  ) {
    if (this.webOptions.resourceUrl) {
      const logsEnabled = this.webOptions.logsEnabled;
      if (logsEnabled) this.doLog('Resource url: ' + this.webOptions.resourceUrl);
      if (accessToken) {
        if (logsEnabled) this.doLog('Access token:', accessToken);
        const self = this;
        const request = new XMLHttpRequest();
        request.onload = function () {
          if (this.status === 200) {
            const resp = JSON.parse(this.response);
            if (logsEnabled) self.doLog('Resource response:', resp);
            if (resp) self.assignResponses(resp, accessToken, authorizationResponse, accessTokenResponse);
            if (logsEnabled) self.doLog(self.MSG_RETURNED_TO_JS, resp);
            resolve(resp);
          } else {
            reject(new Error(this.statusText));
          }
          self.closeWindow();
        };
        request.onerror = function () {
          if (logsEnabled) self.doLog('ERR_GENERAL: ' + this.statusText);
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
      } else {
        if (logsEnabled) {
          this.doLog(
            'No accessToken was provided although you configured a resourceUrl. Remove the resourceUrl from the config.',
          );
        }
        reject(new Error('ERR_NO_ACCESS_TOKEN'));
        this.closeWindow();
      }
    } else {
      // if no resource url exists just return the accessToken response
      const resp: any = {};
      this.assignResponses(resp, accessToken, authorizationResponse, accessTokenResponse);
      if (this.webOptions.logsEnabled) this.doLog(this.MSG_RETURNED_TO_JS, resp);
      resolve(resp);
      this.closeWindow();
    }
  }

  assignResponses(resp: any, accessToken: string, authorizationResponse: any, accessTokenResponse: any = null): void {
    if (authorizationResponse) resp['authorization_response'] = authorizationResponse;
    if (accessTokenResponse) resp['access_token_response'] = accessTokenResponse;
    resp['access_token'] = accessToken;
  }

  async logout(options: OAuth2AuthenticateOptions): Promise<boolean> {
    return new Promise<any>((resolve, _reject) => {
      localStorage.removeItem(WebUtils.getAppId(options));
      resolve(true);
    });
  }

  private closeWindow() {
    window.clearInterval(this.intervalId);
    // Do not force-close when provider reused the same tab; but default behavior is to try closing:
    if (this.storageListenAbort) this.storageListenAbort();
    this.windowHandle?.close();
    this.windowClosedByPlugin = true;
  }

  private doLog(msg: string, obj: any = null) {
    console.log('I/Capacitor/GenericOAuth2Plugin: ' + msg, obj);
  }
}

/**
 * Put the final callback URL into localStorage under `${prefix}:${flowId}`.
 * If `options` is omitted (e.g., used from the plain redirect page), we:
 *  - derive `state` (and optional `app_state`) from `href`
 *  - use default prefix 'oauth2'
 */
export async function submitOAuthCallbackUrl(
  href: string = window.location.href,
  options?: OAuth2AuthenticateOptions,
): Promise<void> {
  let prefix = 'oauth2';
  let state: string | undefined;

  console.log('I/Capacitor/GenericOAuth2Plugin: Submitting callback URL', href);

  // Prefer explicit options if provided
  if (options) {
    try {
      const webOptions = await WebUtils.buildWebOptions(options);
      prefix = webOptions.callbackStoragePrefix ?? prefix;
      state = WebUtils.getUrlParams(href)?.state;
      // figure out how to make this work in the future!! it seems state was always set?
      //   state = webOptions.state || WebUtils.getUrlParams(href)?.state;
    } catch {
      // fall back to parsing
    }
  }

  if (!state) {
    const u = new URL(href);
    state = u.searchParams.get('state')!;
  }

  console.log(`I/Capacitor/GenericOAuth2Plugin: Storing callback URL under key ${prefix}:${state}`);

  if (!state) return;
  try {
    localStorage.setItem(`${prefix}:${state}`, href);
  } catch {
    // ignore quota/blocked errors; opener will timeout
  }
}
