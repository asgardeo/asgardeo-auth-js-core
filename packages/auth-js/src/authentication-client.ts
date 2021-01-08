/**
 * Copyright (c) 2020, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

import { AxiosResponse } from "axios";
import { OP_CONFIG_INITIATED, SIGN_OUT_SUCCESS_PARAM } from "./constants";
import { AuthenticationCore } from "./core";
import { DataLayer } from "./data";
import {
    AuthClientConfig,
    BasicUserInfo,
    CustomGrantConfig,
    DecodedIdTokenPayload,
    OIDCEndpoints,
    SignInConfig,
    Store,
    TokenResponse
} from "./models";

/**
 * This class provides the necessary methods needed to implement authentication.
 */
export class AsgardeoAuthClient<T> {
    private _dataLayer: DataLayer<T>;
    private _authenticationCore: AuthenticationCore<T>;

    private static _instanceID: number;

    /**
     * This is the constructor method that returns an instance of the .
     *
     * @param {AuthClientConfig<T>} config - The config object to initialize with.
     * @param {Store} store - The store object.
     *
     * @example
     * ```
     * const _store: Store = new DataStore();
     * const config = {
     *     signInRedirectURL: "http://localhost:3000/sign-in",
     *     clientHost: "http://localhost:3000",
     *     clientID: "client ID",
     *     serverOrigin: "http://localhost:9443"
     * }
     * const auth = new AsgardeoAuthClient<CustomClientConfig>(config, _store);
     * ```
     *
     * @link https://github.com/asgardeo/asgardeo-auth-js-sdk/tree/master/lib#constructor
     * @preserve
     */
    public constructor(config: AuthClientConfig<T>, store: Store) {
        if (!AsgardeoAuthClient._instanceID) {
            AsgardeoAuthClient._instanceID = 0;
        } else {
            AsgardeoAuthClient._instanceID += 1;
        }
        this._dataLayer = new DataLayer<T>(`instance_${AsgardeoAuthClient._instanceID}`, store);
        this._authenticationCore = new AuthenticationCore(this._dataLayer);
        this._dataLayer.setConfigData(config);
    }

    /**
     * This method returns the `DataLayer` object that allows you to access authentication data.
     *
     * @return {DataLayer} - The `DataLayer` object.
     *
     * @example
     * ```
     * const data = auth.getDataLayer();
     * ```
     *
     * @link https://github.com/asgardeo/asgardeo-auth-js-sdk/tree/master/lib#getDataLayer
     *
     * @memberof AsgardeoAuthClient
     *
     * @preserve
     */
    public getDataLayer(): DataLayer<T> {
        return this._dataLayer;
    }

    /**
     * This is an async method that returns a Promise that resolves with the authorization URL.
     *
     * @param {SignInConfig} config - (Optional) A config object to force initialization and pass
     * custom path parameters such as the fidp parameter.
     *
     * @return {Promise<string>} - A promise that resolves with the authorization URL.
     *
     * @example
     * ```
     * auth.getAuthorizationURL().then((url)=>{
     *  // console.log(url);
     * }).catch((error)=>{
     *  // console.error(error);
     * });
     * ```
     *
     * @link https://github.com/asgardeo/asgardeo-auth-js-sdk/tree/master/lib#getAuthorizationURL
     *
     * @memberof AsgardeoAuthClient
     *
     * @preserve
     */
    public async getAuthorizationURL(config?: SignInConfig): Promise<string> {
        const authRequestConfig = { ...config };
        delete authRequestConfig?.forceInit;

        if (this._dataLayer.getTemporaryDataParameter(OP_CONFIG_INITIATED)) {
            return this._authenticationCore.getAuthorizationURL(authRequestConfig);
        }

        return this._authenticationCore.getOIDCProviderMetaData(config?.forceInit as boolean).then(() => {
            return this._authenticationCore.getAuthorizationURL(authRequestConfig);
        });
    }

    /**
     * This is an async method that sends a request to obtain the access token and returns a Promise
     * that resolves with the token and other relevant data.
     *
     * @param {string} authorizationCode - The authorization code.
     * @param {string} sessionState - The session state.
     *
     * @return {Promise<TokenResponse>} - A Promise that resolves with the token response.
     *
     * @example
     * ```
     * auth.requestAccessToken(authCode, sessionState).then((token)=>{
     *  // console.log(token);
     * }).catch((error)=>{
     *  // console.error(error);
     * });
     * ```
     *
     * @link https://github.com/asgardeo/asgardeo-auth-js-sdk/tree/master/lib#requestAccessToken
     *
     * @memberof AsgardeoAuthClient
     *
     * @preserve
     */
    public requestAccessToken(authorizationCode: string, sessionState: string): Promise<TokenResponse> {
        if (this._dataLayer.getTemporaryDataParameter(OP_CONFIG_INITIATED)) {
            return this._authenticationCore.requestAccessToken(authorizationCode, sessionState);
        }

        return this._authenticationCore.getOIDCProviderMetaData(false).then(() => {
            return this._authenticationCore.requestAccessToken(authorizationCode, sessionState);
        });
    }

    /**
     * This method clears all authentication data and returns the sign-out URL.
     *
     * @return {string} - The sign-out URL.
     *
     * @example
     * ```
     * const signOutUrl = auth.signOut();
     * ```
     *
     * @link https://github.com/asgardeo/asgardeo-auth-js-sdk/tree/master/lib#signOut
     *
     * @memberof AsgardeoAuthClient
     *
     * @preserve
     */
    public signOut(): string {
        return this._authenticationCore.signOut();
    }

    /**
     * This method returns the sign-out URL.
     *
     * **This doesn't clear the authentication data.**
     *
     * @return {string} - The sign-out URL.
     *
     * @example
     * ```
     * const signOutUrl = auth.getSignOutURL();
     * ```
     *
     * @link https://github.com/asgardeo/asgardeo-auth-js-sdk/tree/master/lib#getSignOutURL
     *
     * @memberof AsgardeoAuthClient
     *
     * @preserve
     */
    public getSignOutURL(): string {
        return this._authenticationCore.getSignOutURL();
    }

    /**
     * This method returns OIDC service endpoints that are fetched from teh `.well-known` endpoint.
     *
     * @return {OIDCEndpoints} - An object containing the OIDC service endpoints.
     *
     * @example
     * ```
     * const endpoints = auth.getOIDCServiceEndpoints();
     * ```
     *
     * @link https://github.com/asgardeo/asgardeo-auth-js-sdk/tree/master/lib#getOIDCServiceEndpoints
     *
     * @memberof AsgardeoAuthClient
     *
     * @preserve
     */
    public getOIDCServiceEndpoints(): OIDCEndpoints {
        return this._authenticationCore.getOIDCServiceEndpoints();
    }

    /**
     * This method decodes the payload of the ID token and returns it.
     *
     * @return {DecodedIdTokenPayload} - The decoded ID token payload.
     *
     * @example
     * ```
     * const decodedIdToken = auth.getDecodedIDToken();
     * ```
     *
     * @link https://github.com/asgardeo/asgardeo-auth-js-sdk/tree/master/lib#getDecodedIDToken
     *
     * @memberof AsgardeoAuthClient
     *
     * @preserve
     */
    public getDecodedIDToken(): DecodedIdTokenPayload {
        return this._authenticationCore.getDecodedIDToken();
    }

    /**
     * This method returns the basic user information obtained from the ID token.
     *
     * @return {BasicUserInfo} - An object containing the basic user information.
     *
     * @example
     * ```
     * const userInfo = auth.getBasicUserInfo();
     * ```
     *
     * @link https://github.com/asgardeo/asgardeo-auth-js-sdk/tree/master/lib#getBasicUserInfo
     *
     * @memberof AsgardeoAuthClient
     *
     * @preserve
     */
    public getBasicUserInfo(): BasicUserInfo {
        return this._authenticationCore.getBasicUserInfo();
    }

    /**
     * This method revokes the access token.
     *
     * **This method also clears the authentication data.**
     *
     * @return {Promise<AxiosResponse>} - A Promise that returns the response of the revoke-access-token request.
     *
     * @example
     * ```
     * auth.revokeAccessToken().then((response)=>{
     *  // console.log(response);
     * }).catch((error)=>{
     *  // console.error(error);
     * });
     * ```
     *
     * @link https://github.com/asgardeo/asgardeo-auth-js-sdk/tree/master/lib#revokeAccessToken
     *
     * @memberof AsgardeoAuthClient
     *
     * @preserve
     */
    public revokeAccessToken(): Promise<AxiosResponse> {
        return this._authenticationCore.revokeAccessToken();
    }

    /**
     * This method refreshes the access token and returns a Promise that resolves with the new access
     * token and other relevant data.
     *
     * @return {Promise<TokenResponse>} - A Promise that resolves with the token response.
     *
     * @example
     * ```
     * auth.refreshAccessToken().then((response)=>{
     *  // console.log(response);
     * }).catch((error)=>{
     *  // console.error(error);
     * });
     * ```
     *
     * @link https://github.com/asgardeo/asgardeo-auth-js-sdk/tree/master/lib#refreshAccessToken
     *
     * @memberof AsgardeoAuthClient
     *
     * @preserve
     */
    public refreshAccessToken(): Promise<TokenResponse> {
        return this._authenticationCore.refreshAccessToken();
    }

    /**
     * This method returns the access token.
     *
     * @return {string} - The access token.
     *
     * @example
     * ```
     * const accessToken = auth.getAccessToken();
     * ```
     *
     * @link https://github.com/asgardeo/asgardeo-auth-js-sdk/tree/master/lib#getAccessToken
     *
     * @memberof AsgardeoAuthClient
     *
     * @preserve
     */
    public getAccessToken(): string {
        return this._authenticationCore.getAccessToken();
    }

    /**
     * This method sends a custom-grant request and returns a Promise that resolves with the response
     * depending on the config passed.
     *
     * @param {CustomGrantConfig} config - A config object containing the custom grant configurations.
     *
     * @return {Promise<TokenResponse | AxiosResponse>} - A Promise that resolves with the response depending
     * on your configurations.
     *
     * @example
     * ```
     * const config = {
     *   attachToken: false,
     *   data: {
     *       client_id: "{{clientID}}",
     *       grant_type: "account_switch",
     *       scope: "{{scope}}",
     *       token: "{{token}}",
     *   },
     *   id: "account-switch",
     *   returnResponse: true,
     *   returnsSession: true,
     *   signInRequired: true
     * }
     *
     * auth.requestCustomGrant(config).then((response)=>{
     *  // console.log(response);
     * }).catch((error)=>{
     *  // console.error(error);
     * });
     * ```
     *
     * @link https://github.com/asgardeo/asgardeo-auth-js-sdk/tree/master/lib#requestCustomGrant
     *
     * @memberof AsgardeoAuthClient
     *
     * @preserve
     */
    public requestCustomGrant(config: CustomGrantConfig): Promise<TokenResponse | AxiosResponse> {
        return this._authenticationCore.requestCustomGrant(config);
    }

    /**
     * This method returns if the user is authenticated or not.
     *
     * @return {boolean} - `true` if the user is authenticated, `false` otherwise.
     *
     * @example
     * ```
     * auth.isAuthenticated();
     * ```
     *
     * @link https://github.com/asgardeo/asgardeo-auth-js-sdk/tree/master/lib#isAuthenticated
     *
     * @memberof AsgardeoAuthClient
     *
     * @preserve
     */
    public isAuthenticated(): boolean {
        return this._authenticationCore.isAuthenticated();
    }

    /**
     * This method returns the PKCE code generated during the generation of the authentication URL.
     *
     * @return {string} - The PKCE code.
     *
     * @example
     * ```
     * const pkce = getPKCECode();
     * ```
     *
     * @link https://github.com/asgardeo/asgardeo-auth-js-sdk/tree/master/lib#getPKCECode
     *
     * @memberof AsgardeoAuthClient
     *
     * @preserve
     */
    public getPKCECode(): string {
        return this._authenticationCore.getPKCECode();
    }

    /**
     * This method sets the PKCE code to the data store.
     *
     * @param {string} pkce - The PKCE code.
     *
     * @example
     * ```
     * auth.setPKCECode("pkce_code")
     * ```
     *
     * @link https://github.com/asgardeo/asgardeo-auth-js-sdk/tree/master/lib#setPKCECode
     *
     * @memberof AsgardeoAuthClient
     *
     * @preserve
     */
    public setPKCECode(pkce: string): void {
        this._authenticationCore.setPKCECode(pkce);
    }

    /**
     * This method returns if the sign-out is successful or not.
     *
     * @param {string} signOutRedirectUrl - The URL to which the user has been redirected to after signing-out.
     *
     * **The server appends path parameters to the `signOutRedirectURL` and these path parameters
     *  are required for this method to function.**
     *
     * @return {boolean} - `true` if successful, `false` otherwise.
     *
     * @link https://github.com/asgardeo/asgardeo-auth-js-sdk/tree/master/lib#isSignOutSuccessful
     *
     * @memberof AsgardeoAuthClient
     *
     * @preserve
     */
    public static isSignOutSuccessful(signOutRedirectURL: string): boolean {
        const url = new URL(signOutRedirectURL);
        const stateParam = url.searchParams.get("state");
        const error = Boolean(url.searchParams.get("error"));

        return stateParam && stateParam === SIGN_OUT_SUCCESS_PARAM && !error;
    }

    /**
     * This method updates the configuration that was passed into the constructor when instantiating this class.
     *
     * @param {Partial<AuthClientConfig<T>>} config - A config object to update the SDK configurations with.
     *
     * @example
     * ```
     * const config = {
     *     signInRedirectURL: "http://localhost:3000/sign-in",
     *     clientHost: "http://localhost:3000",
     *     clientID: "client ID",
     *     serverOrigin: "http://localhost:9443"
     * }
     * const auth.updateConfig(config);
     * ```
     * @link https://github.com/asgardeo/asgardeo-auth-js-sdk/tree/master/lib#updateConfig
     *
     * @memberof AsgardeoAuthClient
     *
     * @preserve
     */
    public updateConfig(config: Partial<AuthClientConfig<T>>): void {
        this._authenticationCore.updateConfig(config);
    }
}
