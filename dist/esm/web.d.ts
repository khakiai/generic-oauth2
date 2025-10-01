import { WebPlugin } from '@capacitor/core';
import type { OAuth2AuthenticateOptions, GenericOAuth2Plugin, OAuth2RefreshTokenOptions, ImplicitFlowRedirectOptions } from './definitions';
import type { WebOptions } from './web-utils';
type OAuth2Result = {
    access_token?: string;
    authorization_response?: Record<string, string>;
    access_token_response?: Record<string, any>;
};
export declare class GenericOAuth2Web extends WebPlugin implements GenericOAuth2Plugin {
    private webOptions;
    private windowHandle;
    private intervalId;
    private loopCount;
    private intervalLength;
    private windowClosedByPlugin;
    private readonly MSG_RETURNED_TO_JS;
    /**
     * Get a new access token using an existing refresh token.
     */
    refreshToken(_options: OAuth2RefreshTokenOptions): Promise<any>;
    /**
     * New: Pure redirect consumer. No popup/window required.
     * Call this from your /auth/callback route with the full redirected URL.
     * Returns the same payload shape produced by requestResource/assignResponses.
     */
    consumeRedirectUrl(redirectedUrl: string, options: OAuth2AuthenticateOptions | WebOptions): Promise<OAuth2Result>;
    redirectFlowCodeListener(options: ImplicitFlowRedirectOptions): Promise<any>;
    authenticate(options: OAuth2AuthenticateOptions): Promise<any>;
    syncAuthenticate(options: OAuth2AuthenticateOptions): Promise<any>;
    private getAccessToken;
    private requestResource;
    private fetchResourcePure;
    assignResponses(resp: any, accessToken: string, authorizationResponse: any, accessTokenResponse?: any): void;
    logout(options: OAuth2AuthenticateOptions): Promise<boolean>;
    private closeWindow;
    private doLog;
}
export {};
