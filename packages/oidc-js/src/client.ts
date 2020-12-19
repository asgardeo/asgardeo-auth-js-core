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
    Config,
    CustomGrantConfig,
    DecodedIdTokenPayload,
    OIDCEndpoints,
    OIDC_SCOPE,
    SignInConfig,
    WebWorkerClientConfig
} from ".";
import { MainThreadClient, WebWorkerClient } from "./clients";
import { Hooks, Storage } from "./constants";
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
const DefaultConfig = {
    clientHost: origin,
    clientSecret: null,
    clockTolerance: 60,
    consentDenied: false,
    enablePKCE: true,
    responseMode: null,
    scope: [OIDC_SCOPE],
    validateIDToken: true
};

const PRIMARY_INSTANCE = "primaryInstance";

/**
 * IdentityClient class constructor.
 *
 * @export
 * @class IdentityClient
 * @implements {ConfigInterface} - Configuration interface.
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
     * This method returns the instance of the singleton class.
     *
     * @return {IdentityClient} - Returns the instance of the singleton class.
     *
     * @example
     * ```
     * const auth = IdentityClient.getInstance();
     * ```
     *
     * @link https://github.com/asgardio/asgardio-js-oidc-sdk/tree/master/packages/oidc-js#getinstance
     *
     * @memberof IdentityClient
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
     * This method initializes the `IdentityClient` instance.
     *
     * @param {ConfigInterface} config The config object to initialize with.
     *
     * @return {Promise<boolean>} - Resolves to `true` if initialization is successful.
     *
     * @example
     * ```
     * auth.initialize({
     *     signInRedirectURL: "http://localhost:9443/myaccount/login",
     *     clientHost: "http://localhost:9443/myaccount/",
     *     clientID: "client ID",
     *     serverOrigin: "http://localhost:9443"
     * });
     * ```
     *
     * @link https://github.com/asgardio/asgardio-js-oidc-sdk/tree/master/packages/oidc-js#initialize
     *
     * @memberof IdentityClient
     *
     * @preserve
     */
    public initialize(config: AuthClientConfig<Config>): Promise<boolean> {
        this._storage = config.storage ?? Storage.SessionStorage;
        this._initialized = false;
        this._startedInitialize = true;

        if (!(this._storage === Storage.WebWorker)) {
            this._initialized = true;
            if (!this._client) {
                const mainThreadClientConfig = config as AuthClientConfig<MainThreadClientConfig>;
                this._client = MainThreadClient({ ...DefaultConfig, ...mainThreadClientConfig });
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
     * @link https://github.com/asgardio/asgardio-js-oidc-sdk/tree/master/packages/oidc-js#getuserinfo
     *
     * @memberof IdentityClient
     *
     * @preserve
     */
    public async getBasicUserInfo(): Promise<BasicUserInfo> {
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
     * @see {@link https://github.com/asgardio/asgardio-js-oidc-sdk/tree/master/packages/oidc-js#on}
     *
     * @param {SignInConfig} params - The sign-in config.
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
     * @link https://github.com/asgardio/asgardio-js-oidc-sdk/tree/master/packages/oidc-js#signin
     *
     * @memberof IdentityClient
     *
     * @preserve
     */
    public async signIn(
        params?: SignInConfig,
        authorizationCode?: string,
        sessionState?: string,
        signInRedirectURL?: string
    ): Promise<BasicUserInfo> {
        if (!this._startedInitialize) {
            return Promise.reject("The object has not been initialized yet.");
        }

        let iterationToWait = 0;

        const sleep = (): Promise<any> => {
            return new Promise((resolve) => setTimeout(resolve, 500));
        };

        while (!this._initialized) {
            if (iterationToWait === 21) {
                // eslint-disable-next-line no-console
                console.warn("It is taking longer than usual for the object to be initialized");
            }
            await sleep();
            iterationToWait++;
        }

        return this._client
            .signIn(params, authorizationCode, sessionState, signInRedirectURL)
            .then((response: BasicUserInfo) => {
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
     * @see {@link https://github.com/asgardio/asgardio-js-oidc-sdk/tree/master/packages/oidc-js#on}
     *
     * @return {Promise<boolean>} - Returns a promise that resolves with `true` if sign out is successful.
     *
     * @example
     * ```
     * auth.signOut();
     * ```
     *
     * @link https://github.com/asgardio/asgardio-js-oidc-sdk/tree/master/packages/oidc-js#signout
     *
     * @memberof IdentityClient
     *
     * @preserve
     */
    public async signOut(signOutRedirectURL?: string): Promise<boolean> {
        const signOutResponse = await this._client.signOut(signOutRedirectURL);
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
     * @link https://github.com/asgardio/asgardio-js-oidc-sdk/tree/master/packages/oidc-js#httprequest
     *
     * @memberof IdentityClient
     *
     * @preserve
     */
    public async httpRequest(config: HttpRequestConfig): Promise<HttpResponse> {
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
     * @link https://github.com/asgardio/asgardio-js-oidc-sdk/tree/master/packages/oidc-js#httprequestall
     *
     * @memberof IdentityClient
     *
     * @preserve
     */
    public async httpRequestAll(config: HttpRequestConfig[]): Promise<HttpResponse[]> {
        return this._client.httpRequestAll(config);
    }

    /**
     * This method allows you to send a request with a custom grant.
     *
     * @param {CustomGrantRequestParams} requestParams - The request parameters.
     *
     * @return {Promise< boolean | HttpResponse<any> | SignInResponse>} - A Promise that resolves with
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
     * @link https://github.com/asgardio/asgardio-js-oidc-sdk/tree/master/packages/oidc-js#customgrant
     *
     * @memberof IdentityClient
     *
     * @preserve
     */
    public async requestCustomGrant(
        requestParams: CustomGrantConfig
    ): Promise<boolean | HttpResponse<any> | BasicUserInfo> {
        if (!requestParams.id) {
            throw Error("No ID specified for the custom grant.");
        }

        const customGrantResponse = await this._client.requestCustomGrant(requestParams);

        this._onCustomGrant?.get(requestParams.id) &&
            this._onCustomGrant?.get(requestParams.id)(this._onCustomGrant?.get(requestParams.id));

        return customGrantResponse;
    }

    /**
     * This method ends a user session. The access token is revoked and the session information is destroyed.
     *
     * **To fire a callback function after ending user session, use the `on()` method.**
     * **To learn more about the `on()` method:**
     * @see {@link https://github.com/asgardio/asgardio-js-oidc-sdk/tree/master/packages/oidc-js#on}
     *
     * @return {Promise<boolean>} - A promise that resolves with `true` if the process is successful.
     *
     * @example
     * ```
     * auth.endUserSession();
     * ```
     *
     * @link https://github.com/asgardio/asgardio-js-oidc-sdk/tree/master/packages/oidc-js#endusersession
     *
     * @memberof IdentityClient
     *
     * @preserve
     */
    public async revokeAccessToken(): Promise<boolean> {
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
     * @link https://github.com/asgardio/asgardio-js-oidc-sdk/tree/master/packages/oidc-js#getserviceendpoints
     *
     * @memberof IdentityClient
     *
     * @preserve
     */
    public async getOIDCServiceEndpoints(): Promise<OIDCEndpoints> {
        return this._client.getOIDCServiceEndpoints();
    }

    /**
     * This methods returns the Axios http client.
     *
     * @return {HttpClientInstance} - The Axios HTTP client.
     *
     * @memberof IdentityClient
     *
     * @preserve
     */
    public getHttpClient(): HttpClientInstance {
        if (this._initialized) {
            if (this._storage !== Storage.WebWorker) {
                const mainThreadClient = this._client as MainThreadClientInterface;
                return mainThreadClient.getHttpClient();
            }

            throw Error("Http client cannot be returned when the storage is set to web worker");
        }

        throw Error("Identity Client has not been initialized yet");
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
     * @link https://github.com/asgardio/asgardio-js-oidc-sdk/tree/master/packages/oidc-js#getdecodedidtoken
     *
     * @memberof IdentityClient
     *
     * @preserve
     */
    public async getDecodedIDToken(): Promise<DecodedIdTokenPayload> {
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
     * @link https://github.com/asgardio/asgardio-js-oidc-sdk/tree/master/packages/oidc-js#getaccesstoken
     *
     * @memberof IdentityClient
     *
     * @preserve
     */
    public async getAccessToken(): Promise<string> {
        if (this._storage === Storage.WebWorker) {
            return Promise.reject("The access token cannot be obtained when the storage type is set to webWorker.");
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
     * @link https://github.com/asgardio/asgardio-js-oidc-sdk/tree/master/packages/oidc-js#refreshtoken
     *
     * @memberof IdentityClient
     *
     * @preserve
     */
    public async refreshAccessToken(): Promise<BasicUserInfo> {
        return this._client.refreshAccessToken();
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
     * @link https://github.com/asgardio/asgardio-js-oidc-sdk/tree/master/packages/oidc-js#on
     *
     * @memberof IdentityClient
     *
     * @preserve
     */
    public on(hook: Hooks.CustomGrant, callback: (response?: any) => void, id: string): void;
    public on(
        hook:
            | Hooks.EndUserSession
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
                case Hooks.EndUserSession:
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
                    throw Error("No such hook found");
            }
        } else {
            throw Error("The callback function is not a valid function.");
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
     * @link https://github.com/asgardio/asgardio-js-oidc-sdk/tree/master/packages/oidc-js#enableHttpHandler
     *
     * @memberof IdentityClient
     *
     * @preserve
     */
    public async enableHttpHandler(): Promise<boolean> {
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
     * @link https://github.com/asgardio/asgardio-js-oidc-sdk/tree/master/packages/oidc-js#disableHttpHandler
     *
     * @memberof IdentityClient
     *
     * @preserve
     */
    public async disableHttpHandler(): Promise<boolean> {
        return this._client.disableHttpHandler();
    }
}
