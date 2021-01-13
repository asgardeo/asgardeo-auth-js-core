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

import {
    AuthClientConfig,
    BasicUserInfo,
    CustomGrantConfig,
    DecodedIDTokenPayload,
    OIDCEndpoints,
    OIDC_SCOPE,
    SignInConfig
} from "@asgardeo/auth-js";
import { Config, WebWorkerClientConfig } from ".";
import { MainThreadClient, WebWorkerClient } from "./clients";
import { Hooks, Storage } from "./constants";
import { AsgardeoSPAException } from "./exception";
import { HttpClientInstance } from "./http-client";
import {
    HttpError,
    HttpRequestConfig,
    HttpResponse,
    MainThreadClientConfig,
    MainThreadClientInterface,
    WebWorkerClientInterface
} from "./models";
import { SPAUtils } from "./utils";

/**
 * Default configurations.
 */
const DefaultConfig: Partial<AuthClientConfig<Config>> = {
    checkSessionInterval: 3,
    clientHost: origin,
    clientSecret: null,
    clockTolerance: 60,
    enablePKCE: true,
    responseMode: null,
    scope: [OIDC_SCOPE],
    validateIDToken: true
};

const PRIMARY_INSTANCE = "primaryInstance";

/**
 * This class provides the necessary methods to implement authentication in a Single Page Application.
 *
 * @export
 * @class AsgardeoSPAClient
 */
export class AsgardeoSPAClient {
    private static _instances: Map<string, AsgardeoSPAClient> = new Map<string, AsgardeoSPAClient>();
    private _client: WebWorkerClientInterface | MainThreadClientInterface;
    private _storage: Storage;
    private _initialized: boolean;
    private _startedInitialize: boolean = false;
    private _onSignInCallback: (response: BasicUserInfo) => void;
    private _onSignOutCallback: () => void;
    private _onEndUserSession: (response: any) => void;
    private _onInitialize: (response: boolean) => void;
    private _onCustomGrant: Map<string, (response: any) => void> = new Map();
    private _onHttpRequestStart: () => void;
    private _onHttpRequestSuccess: (response: HttpResponse) => void;
    private _onHttpRequestFinish: () => void;
    private _onHttpRequestError: (error: HttpError) => void;
    private _instanceID: string;

    // eslint-disable-next-line @typescript-eslint/no-empty-function
    private constructor(id: string) {
        this._instanceID = id;
    }

    /**
     * This method specifies if the `AsgardeoSPAClient` has been initialized or not.
     *
     * @return {Promise<boolean>} - Resolves to `true` if the client has been initialized.
     *
     * @memberof AsgardeoSPAClient
     *
     * @private
     */
    private async _isInitialized(): Promise<boolean> {
        if (!this._startedInitialize) {
            return false;
        }

        let iterationToWait = 0;

        const sleep = (): Promise<any> => {
            return new Promise((resolve) => setTimeout(resolve, 1000));
        };

        while (!this._initialized) {
            if (iterationToWait === 10) {
                // eslint-disable-next-line no-console
                console.warn("It is taking longer than usual for the object to be initialized");
            }
            await sleep();
            iterationToWait++;
        }

        return true;
    }

    /**
     *  This method checks if the SDK is initialized and the user is authenticated.
     *
     * @return {Promise<boolean>} - A Promise that resolves with `true` if the SDK is initialized and the
     * user is authenticated.
     *
     * @memberof AsgardeoSPAClient
     *
     * @private
     */
    private async _validateMethod(): Promise<boolean> {
        if (!(await this._isInitialized())) {
            return Promise.reject();
        }

        if (!(await this.isAuthenticated())) {
            return Promise.reject();
        }

        return true;
    }

    /**
     * This method returns the instance of the singleton class.
     *
     * @return {AsgardeoSPAClient} - Returns the instance of the singleton class.
     *
     * @example
     * ```
     * const auth = AsgardeoSPAClient.getInstance();
     * ```
     *
     * @link https://github.com/asgardeo/asgardeo-auth-spa-sdk/tree/master/lib/oidc-js#getinstance
     *
     * @memberof AsgardeoSPAClient
     *
     * @preserve
     */
    public static getInstance(id?: string): AsgardeoSPAClient {
        if (id && this._instances?.get(id)) {
            return this._instances.get(id);
        } else if (!id && this._instances?.get(PRIMARY_INSTANCE)) {
            return this._instances.get(PRIMARY_INSTANCE);
        }

        if (id) {
            this._instances.set(id, new AsgardeoSPAClient(id));

            return this._instances.get(id);
        }

        this._instances.set(PRIMARY_INSTANCE, new AsgardeoSPAClient(PRIMARY_INSTANCE));

        return this._instances.get(PRIMARY_INSTANCE);
    }

    /**
     * This method initializes the `AsgardeoSPAClient` instance.
     *
     * @param {ConfigInterface} config The config object to initialize with.
     *
     * @return {Promise<boolean>} - Resolves to `true` if initialization is successful.
     *
     * @example
     * ```
     * auth.initialize({
     *     signInRedirectURL: "http://localhost:3000/sign-in",
     *     clientHost: "http://localhost:3000",
     *     clientID: "client ID",
     *     serverOrigin: "http://localhost:9443"
     * });
     * ```
     *
     * @link https://github.com/asgardeo/asgardeo-auth-spa-sdk/tree/master/lib/oidc-js#initialize
     *
     * @memberof AsgardeoSPAClient
     *
     * @preserve
     */
    public async initialize(config: AuthClientConfig<Config>): Promise<boolean> {
        this._storage = config.storage ?? Storage.SessionStorage;
        this._initialized = false;
        this._startedInitialize = true;

        if (!(this._storage === Storage.WebWorker)) {
            this._initialized = true;
            if (!this._client) {
                const mainThreadClientConfig = config as AuthClientConfig<MainThreadClientConfig>;
                const defaultConfig = { ...DefaultConfig } as Partial<AuthClientConfig<MainThreadClientConfig>>;
                this._client = await MainThreadClient({ ...defaultConfig, ...mainThreadClientConfig });
            }

            if (this._onInitialize) {
                this._onInitialize(true);
            }

            return Promise.resolve(true);
        } else {
            if (!this._client) {
                const webWorkerClientConfig = config as AuthClientConfig<WebWorkerClientConfig>;
                this._client = WebWorkerClient({
                    ...DefaultConfig,
                    ...webWorkerClientConfig
                }) as WebWorkerClientInterface;

                return this._client
                    .initialize()
                    .then(() => {
                        if (this._onInitialize) {
                            this._onInitialize(true);
                        }
                        this._initialized = true;

                        return Promise.resolve(true);
                    })
                    .catch((error) => {
                        return Promise.reject(error);
                    });
            }

            return Promise.resolve(true);
        }
    }

    /**
     * This method returns a Promise that resolves with the basic user information obtained from the ID token.
     *
     * @return {Promise<BasicUserInfo>} - A promise that resolves with the user information.
     *
     * @example
     * ```
     * auth.getBasicUserInfo().then((response) => {
     *    // console.log(response);
     * }).catch((error) => {
     *    // console.error(error);
     * });
     * ```
     *
     * @link https://github.com/asgardeo/asgardeo-auth-spa-sdk/tree/master/lib/oidc-js#getuserinfo
     *
     * @memberof AsgardeoSPAClient
     *
     * @preserve
     */
    public async getBasicUserInfo(): Promise<BasicUserInfo> {
        await this._validateMethod();

        return this._client.getBasicUserInfo();
    }

    /**
     * This method initiates the authentication flow. This should be called twice.
     *  1. To initiate the authentication flow.
     *  2. To obtain the access token after getting the authorization code.
     *
     * To satisfy the second condition, one of the two strategies mentioned below can be used:
     *  1. Redirect the user back to the same login page that initiated the authentication flow.
     *  2. Call the `signIn()` method in the page the user is redirected to after authentication.
     *
     * **To fire a callback function after signing in, use the `on()` method.**
     * **To learn more about the `on()` method:**
     * @see {@link https://github.com/asgardeo/asgardeo-auth-spa-sdk/tree/master/lib/oidc-js#on}
     *
     * @param {SignInConfig} config - The sign-in config.
     * The `SignInConfig` object has these two attributes in addition to any custom key-value pairs.
     *  1. fidp - Specifies the FIDP parameter that is used to take the user directly to an IdP login page.
     *  2. forceInit: Specifies if the OIDC Provider Meta Data should be loaded again from the `well-known`
     * endpoint.
     *  3. Any other parameters that should be appended to the authorization request.
     *
     * @return {Promise<BasicUserInfo>} - A promise that resolves with the user information.
     *
     * @example
     * ```
     * auth.signIn();
     * ```
     *
     * @link https://github.com/asgardeo/asgardeo-auth-spa-sdk/tree/master/lib/oidc-js#signin
     *
     * @memberof AsgardeoSPAClient
     *
     * @preserve
     */
    public async signIn(
        config?: SignInConfig,
        authorizationCode?: string,
        sessionState?: string
    ): Promise<BasicUserInfo> {
        await this._isInitialized();

        return this._client.signIn(config, authorizationCode, sessionState).then((response: BasicUserInfo) => {
            if (this._onSignInCallback) {
                if (response.allowedScopes || response.displayName || response.email || response.username) {
                    this._onSignInCallback(response);
                }
            }

            return response;
        });
    }

    /**
     * This method initiates the sign-out flow.
     *
     * **To fire a callback function after signing out, use the `on()` method.**
     * **To learn more about the `on()` method:**
     * @see {@link https://github.com/asgardeo/asgardeo-auth-spa-sdk/tree/master/lib/oidc-js#on}
     *
     * @return {Promise<boolean>} - Returns a promise that resolves with `true` if sign out is successful.
     *
     * @example
     * ```
     * auth.signOut();
     * ```
     *
     * @link https://github.com/asgardeo/asgardeo-auth-spa-sdk/tree/master/lib/oidc-js#signout
     *
     * @memberof AsgardeoSPAClient
     *
     * @preserve
     */
    public async signOut(): Promise<boolean> {
        await this._validateMethod();

        const signOutResponse = await this._client.signOut();
        this._onSignOutCallback && this._onSignOutCallback();

        return signOutResponse;
    }

    /**
     * This method sends an API request to a protected endpoint.
     * The access token is automatically attached to the header of the request.
     * This is the only way by which protected endpoints can be accessed
     * when the web worker is used to store session information.
     *
     * @param {HttpRequestConfig} config -  The config object containing attributes necessary to send a request.
     *
     * @return {Promise<HttpResponse>} - Returns a Promise that resolves with the response to the request.
     *
     * @example
     * ```
     *  const requestConfig = {
     *      headers: {
     *          "Accept": "application/json",
     *          "Access-Control-Allow-Origin": "https://localhost:9443/myaccount",
     *          "Content-Type": "application/scim+json"
     *      },
     *      method: "GET",
     *      url: "https://localhost:9443/scim2/me"
     *  };
     *
     *  return auth.httpRequest(requestConfig)
     *     .then((response) => {
     *           // console.log(response);
     *      })
     *      .catch((error) => {
     *           // console.error(error);
     *      });
     * ```
     *
     * @link https://github.com/asgardeo/asgardeo-auth-spa-sdk/tree/master/lib/oidc-js#httprequest
     *
     * @memberof AsgardeoSPAClient
     *
     * @preserve
     */
    public async httpRequest(config: HttpRequestConfig): Promise<HttpResponse> {
        await this._validateMethod();

        return this._client.httpRequest(config);
    }

    /**
     * This method sends multiple API requests to a protected endpoint.
     * The access token is automatically attached to the header of the request.
     * This is the only way by which multiple requests can be sent to protected endpoints
     * when the web worker is used to store session information.
     *
     * @param {HttpRequestConfig[]} config -  The config object containing attributes necessary to send a request.
     *
     * @return {Promise<HttpResponse[]>} - Returns a Promise that resolves with the responses to the requests.
     *
     * @example
     * ```
     *  const requestConfig = {
     *      headers: {
     *          "Accept": "application/json",
     *          "Content-Type": "application/scim+json"
     *      },
     *      method: "GET",
     *      url: "https://localhost:9443/scim2/me"
     *  };
     *
     *  const requestConfig2 = {
     *      headers: {
     *          "Accept": "application/json",
     *          "Content-Type": "application/scim+json"
     *      },
     *      method: "GET",
     *      url: "https://localhost:9443/scim2/me"
     *  };
     *
     *  return auth.httpRequest([requestConfig, requestConfig2])
     *     .then((responses) => {
     *           response.forEach((response)=>{
     *              // console.log(response);
     *           });
     *      })
     *      .catch((error) => {
     *           // console.error(error);
     *      });
     * ```
     *
     * @link https://github.com/asgardeo/asgardeo-auth-spa-sdk/tree/master/lib/oidc-js#httprequestall
     *
     * @memberof AsgardeoSPAClient
     *
     * @preserve
     */
    public async httpRequestAll(config: HttpRequestConfig[]): Promise<HttpResponse[]> {
        await this._validateMethod();

        return this._client.httpRequestAll(config);
    }

    /**
     * This method allows you to send a request with a custom grant.
     *
     * @param {CustomGrantRequestParams} config - The request parameters.
     *
     * @return {Promise<HttpResponse<any> | SignInResponse>} - A Promise that resolves with
     * the value returned by the custom grant request.
     *
     * @example
     * ```
     * auth.customGrant({
     *   attachToken: false,
     *   data: {
     *       client_id: "{{clientId}}",
     *       grant_type: "account_switch",
     *       scope: "{{scope}}",
     *       token: "{{token}}",
     *   },
     *   id: "account-switch",
     *   returnResponse: true,
     *   returnsSession: true,
     *   signInRequired: true
     * });
     * ```
     *
     * @link https://github.com/asgardeo/asgardeo-auth-spa-sdk/tree/master/lib/oidc-js#customgrant
     *
     * @memberof AsgardeoSPAClient
     *
     * @preserve
     */
    public async requestCustomGrant(config: CustomGrantConfig): Promise<HttpResponse<any> | BasicUserInfo> {
        if (config.signInRequired) {
            await this._validateMethod();
        } else {
            await this._validateMethod();
        }

        if (!config.id) {
            return Promise.reject(
                new AsgardeoSPAException(
                    "AUTH_CLIENT-RCG-NF01",
                    "client",
                    "requestCustomGrant",
                    "The custom grant request id not found.",
                    "The id attribute of the custom grant config object passed as an argument should have a value."
                )
            );
        }

        const customGrantResponse = await this._client.requestCustomGrant(config);

        this._onCustomGrant?.get(config.id) && this._onCustomGrant?.get(config.id)(this._onCustomGrant?.get(config.id));

        return customGrantResponse;
    }

    /**
     * This method ends a user session. The access token is revoked and the session information is destroyed.
     *
     * **To fire a callback function after ending user session, use the `on()` method.**
     * **To learn more about the `on()` method:**
     * @see {@link https://github.com/asgardeo/asgardeo-auth-spa-sdk/tree/master/lib/oidc-js#on}
     *
     * @return {Promise<boolean>} - A promise that resolves with `true` if the process is successful.
     *
     * @example
     * ```
     * auth.endUserSession();
     * ```
     *
     * @link https://github.com/asgardeo/asgardeo-auth-spa-sdk/tree/master/lib/oidc-js#endusersession
     *
     * @memberof AsgardeoSPAClient
     *
     * @preserve
     */
    public async revokeAccessToken(): Promise<boolean> {
        await this._validateMethod();

        const revokeAccessToken = await this._client.revokeAccessToken();
        this._onEndUserSession && this._onEndUserSession(revokeAccessToken);

        return revokeAccessToken;
    }

    /**
     * This method returns a Promise that resolves with an object containing the service endpoints.
     *
     * @return {Promise<ServiceResourcesType} - A Promise that resolves with an object containing the service endpoints.
     *
     * @example
     * ```
     * auth.getServiceEndpoints().then((endpoints) => {
     *      // console.log(endpoints);
     *  }).error((error) => {
     *      // console.error(error);
     *  });
     * ```
     *
     * @link https://github.com/asgardeo/asgardeo-auth-spa-sdk/tree/master/lib/oidc-js#getserviceendpoints
     *
     * @memberof AsgardeoSPAClient
     *
     * @preserve
     */
    public async getOIDCServiceEndpoints(): Promise<OIDCEndpoints> {
        await this._isInitialized();

        return this._client.getOIDCServiceEndpoints();
    }

    /**
     * This methods returns the Axios http client.
     *
     * @return {HttpClientInstance} - The Axios HTTP client.
     *
     * @memberof AsgardeoSPAClient
     *
     * @preserve
     */
    public getHttpClient(): HttpClientInstance {
        if (this._client) {
            if (this._storage !== Storage.WebWorker) {
                const mainThreadClient = this._client as MainThreadClientInterface;
                return mainThreadClient.getHttpClient();
            }

            throw new AsgardeoSPAException(
                "AUTH_CLIENT-GHC-IV01",
                "client",
                "getHttpClient",
                "Http client cannot be returned.",
                "The http client cannot be returned when the storage type is set to webWorker."
            );
        }

        throw new AsgardeoSPAException(
            "AUTH_CLIENT-GHC-NF02",
            "client",
            "getHttpClient",
            "The SDK is not initialized.",
            "The SDK has not been initialized yet. Initialize the SDK suing the initialize method " +
                "before calling this method."
        );
    }

    /**
     * This method decodes the payload of the id token and returns it.
     *
     * @return {Promise<DecodedIdTokenPayloadInterface>} - A Promise that resolves with
     * the decoded payload of the id token.
     *
     * @example
     * ```
     * auth.getDecodedIDToken().then((response)=>{
     *     // console.log(response);
     * }).catch((error)=>{
     *     // console.error(error);
     * });
     * ```
     * @link https://github.com/asgardeo/asgardeo-auth-spa-sdk/tree/master/lib/oidc-js#getdecodedidtoken
     *
     * @memberof AsgardeoSPAClient
     *
     * @preserve
     */
    public async getDecodedIDToken(): Promise<DecodedIDTokenPayload> {
        await this._validateMethod();

        return this._client.getDecodedIDToken();
    }

    /**
     * This method return a Promise that resolves with the access token.
     *
     * **This method will not return the access token if the storage type is set to `webWorker`.**
     *
     * @return {Promise<string>} - A Promise that resolves with the access token.
     *
     * @example
     * ```
     *   auth.getAccessToken().then((token) => {
     *       // console.log(token);
     *   }).catch((error) => {
     *       // console.error(error);
     *   });
     * ```
     *
     * @link https://github.com/asgardeo/asgardeo-auth-spa-sdk/tree/master/lib/oidc-js#getaccesstoken
     *
     * @memberof AsgardeoSPAClient
     *
     * @preserve
     */
    public async getAccessToken(): Promise<string> {
        await this._validateMethod();

        if ([Storage.WebWorker, Storage.BrowserMemory].includes(this._storage)) {
            return Promise.reject(
                new AsgardeoSPAException(
                    "AUTH_CLIENT-GAT-IV01",
                    "client",
                    "getAccessToken",
                    "The access token cannot be returned.",
                    "The access token cannot be returned when the storage type is set to webWorker or browserMemory."
                )
            );
        }
        const mainThreadClient = this._client as MainThreadClientInterface;

        return mainThreadClient.getAccessToken();
    }

    /**
     * This method refreshes the access token.
     *
     * @return {TokenResponseInterface} - A Promise that resolves with an object containing
     * information about the refreshed access token.
     *
     * @example
     * ```
     * auth.refreshToken().then((response)=>{
     *      // console.log(response);
     * }).catch((error)=>{
     *      // console.error(error);
     * });
     * ```
     *
     * @link https://github.com/asgardeo/asgardeo-auth-spa-sdk/tree/master/lib/oidc-js#refreshtoken
     *
     * @memberof AsgardeoSPAClient
     *
     * @preserve
     */
    public async refreshAccessToken(): Promise<BasicUserInfo> {
        await this._validateMethod();

        return this._client.refreshAccessToken();
    }

    /**
     * This method specifies if the user is authenticated or not.
     *
     * @return {Promise<boolean>} - A Promise that resolves with `true` if the user is authenticated.
     *
     * @memberof AsgardeoSPAClient
     *
     * @preserve
     */
    public async isAuthenticated(): Promise<boolean> {
        await this._isInitialized();

        return this._client.isAuthenticated();
    }

    /**
     * This method attaches a callback function to an event hook that fires the callback when the event happens.
     *
     * @param {Hooks.CustomGrant} hook - The name of the hook.
     * @param {(response?: any) => void} callback - The callback function.
     * @param {string} id (optional) - The id of the hook. This is used when multiple custom grants are used.
     *
     * @example
     * ```
     * auth.on("sign-in", (response)=>{
     *      // console.log(response);
     * });
     * ```
     *
     * @link https://github.com/asgardeo/asgardeo-auth-spa-sdk/tree/master/lib/oidc-js#on
     *
     * @memberof AsgardeoSPAClient
     *
     * @preserve
     */
    public on(hook: Hooks.CustomGrant, callback: (response?: any) => void, id: string): void;
    public on(
        hook:
            | Hooks.RevokeAccessToken
            | Hooks.HttpRequestError
            | Hooks.HttpRequestFinish
            | Hooks.HttpRequestStart
            | Hooks.HttpRequestSuccess
            | Hooks.Initialize
            | Hooks.SignIn
            | Hooks.SignOut,
        callback: (response?: any) => void
    ): void;
    public on(hook: Hooks, callback: (response?: any) => void, id?: string): void {
        if (callback && typeof callback === "function") {
            switch (hook) {
                case Hooks.SignIn:
                    this._onSignInCallback = callback;
                    break;
                case Hooks.SignOut:
                    this._onSignOutCallback = callback;
                    if (SPAUtils.isSignOutSuccessful()) {
                        this._onSignOutCallback();
                    }
                    break;
                case Hooks.RevokeAccessToken:
                    this._onEndUserSession = callback;
                    break;
                case Hooks.Initialize:
                    this._onInitialize = callback;
                    break;
                case Hooks.HttpRequestError:
                    if (this._storage === Storage.WebWorker) {
                        this._client.setHttpRequestErrorCallback(callback);
                    }

                    this._onHttpRequestError = callback;
                    break;
                case Hooks.HttpRequestFinish:
                    if (this._storage === Storage.WebWorker) {
                        this._client.setHttpRequestFinishCallback(callback);
                    }

                    this._onHttpRequestFinish = callback;
                    break;
                case Hooks.HttpRequestStart:
                    if (this._storage === Storage.WebWorker) {
                        this._client.setHttpRequestStartCallback(callback);
                    }

                    this._onHttpRequestStart = callback;
                    break;
                case Hooks.HttpRequestSuccess:
                    if (this._storage === Storage.WebWorker) {
                        this._client.setHttpRequestSuccessCallback(callback);
                    }

                    this._onHttpRequestSuccess = callback;
                    break;
                case Hooks.CustomGrant:
                    this._onCustomGrant.set(id, callback);
                    break;
                default:
                    throw new AsgardeoSPAException(
                        "AUTH_CLIENT-ON-IV01",
                        "client",
                        "on",
                        "Invalid hook.",
                        "The provided hook is invalid."
                    );
            }
        } else {
            throw new AsgardeoSPAException(
                "AUTH_CLIENT-ON-IV02",
                "client",
                "on",
                "Invalid callback function.",
                "The provided callback function is invalid."
            );
        }
    }

    /**
     * This method enables callback functions attached to the http client.
     *
     * @return {Promise<boolean>} - A promise that resolves with True.
     *
     * @example
     * ```
     * auth.enableHttpHandler();
     * ```
     *
     * @link https://github.com/asgardeo/asgardeo-auth-spa-sdk/tree/master/lib/oidc-js#enableHttpHandler
     *
     * @memberof AsgardeoSPAClient
     *
     * @preserve
     */
    public async enableHttpHandler(): Promise<boolean> {
        await this._isInitialized();

        return this._client.enableHttpHandler();
    }

    /**
     * This method disables callback functions attached to the http client.
     *
     * @return {Promise<boolean>} - A promise that resolves with True.
     *
     * @example
     * ```
     * auth.disableHttpHandler();
     * ```
     *
     * @link https://github.com/asgardeo/asgardeo-auth-spa-sdk/tree/master/lib/oidc-js#disableHttpHandler
     *
     * @memberof AsgardeoSPAClient
     *
     * @preserve
     */
    public async disableHttpHandler(): Promise<boolean> {
        await this._isInitialized();

        return this._client.disableHttpHandler();
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
     * @link https://github.com/asgardeo/asgardeo-auth-spa-sdk/tree/master/lib#updateConfig
     *
     * @memberof AsgardeoAuthClient
     *
     * @preserve
     */
    public async updateConfig(config: Partial<AuthClientConfig<Config>>): Promise<void> {
        await this._isInitialized();
        if (this._storage === Storage.WebWorker) {
            const client = this._client as WebWorkerClientInterface;
            await client.updateConfig(config as Partial<AuthClientConfig<WebWorkerClientConfig>>);
        } else {
            const client = this._client as WebWorkerClientInterface;
            await client.updateConfig(config as Partial<AuthClientConfig<WebWorkerClientConfig>>);
        }

        return;
    }
}
