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
    ACCESS_TOKEN,
    AUTHORIZATION_CODE_TYPE,
    Hooks,
    OIDC_SCOPE,
    REFRESH_TOKEN,
    Storage
}from "./constants";
import { isWebWorkerConfig } from "./helpers";
import { HttpClient, HttpClientInstance } from "./http-client";
import {
    ConfigInterface,
    CustomGrantRequestParams,
    DecodedIdTokenPayloadInterface,
    HttpError,
    HttpRequestConfig,
    HttpResponse,
    ServiceResourcesType,
    SignInResponse,
    TokenResponseInterface,
    UserInfo,
    WebWorkerClientInterface
}from "./models";
import {
    customGrant as customGrantUtil,
    endAuthenticatedSession,
    getAccessToken as getAccessTokenUtil,
    getDecodedIDToken,
    getServiceEndpoints,
    getSessionParameter,
    getUserInfo as getUserInfoUtil,
    handleSignIn,
    handleSignOut,
    isLoggedOut,
    resetOPConfiguration,
    sendRefreshTokenRequest,
    sendRevokeTokenRequest
} from "./utils";
import { WebWorkerClient } from "./worker";

/**
 * Default configurations.
 */
const DefaultConfig = {
    authorizationType: AUTHORIZATION_CODE_TYPE,
    clientHost: origin,
    clientSecret: null,
    clockTolerance: 60,
    consentDenied: false,
    enablePKCE: true,
    responseMode: null,
    scope: [OIDC_SCOPE],
    validateIDToken: true
};

/**
 * IdentityClient class constructor.
 *
 * @export
 * @class IdentityClient
 * @implements {ConfigInterface} - Configuration interface.
 */
export class IdentityClient {
    private _authConfig: ConfigInterface;
    private static _instance: IdentityClient;
    private _client: WebWorkerClientInterface;
    private _storage: Storage;
    private _initialized: boolean;
    private _startedInitialize: boolean = false;
    private _onSignInCallback: (response: UserInfo) => void;
    private _onSignOutCallback: () => void;
    private _onEndUserSession: (response: any) => void;
    private _onInitialize: (response: boolean) => void;
    private _onCustomGrant: Map<string, (response: any) => void> = new Map();
    private _onHttpRequestStart: () => void;
    private _onHttpRequestSuccess: (response: HttpResponse) => void;
    private _onHttpRequestFinish: () => void;
    private _onHttpRequestError: (error: HttpError) => void;
    private _httpClient: HttpClientInstance;

    // eslint-disable-next-line @typescript-eslint/no-empty-function
    private constructor() {}

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
    public static getInstance(): IdentityClient {
        if (this._instance) {
            return this._instance;
        }

        this._instance = new IdentityClient();

        return this._instance;
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
    public initialize(config: ConfigInterface): Promise<boolean> {
        if (!config.signOutRedirectURL) {
            config.signOutRedirectURL = config.signInRedirectURL;
        }

        this._storage = config.storage ?? Storage.SessionStorage;
        this._initialized = false;
        this._startedInitialize = true;

        const attachToken = (request: HttpRequestConfig): void => {
            request.headers = {
                ...request.headers,
                Authorization: `Bearer ${getSessionParameter(ACCESS_TOKEN, config)}`
            };
        };

        if (!isWebWorkerConfig(config)) {
            this._authConfig = { ...DefaultConfig, ...config };
            this._initialized = true;
            this._httpClient = HttpClient.getInstance();
            this._httpClient.init(
                true,
                attachToken,
                this._onHttpRequestStart,
                this._onHttpRequestSuccess,
                this._onHttpRequestError,
                this._onHttpRequestFinish
            );

            if (this._onInitialize) {
                this._onInitialize(true);
            }

            return Promise.resolve(true);
        } else {
            this._client = WebWorkerClient.getInstance();

            return this._client
                .initialize({ ...DefaultConfig, ...config })
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
    }

    /**
     * This method returns a Promise that resolves with the user information obtained from the ID token.
     *
     * @return {Promise<UserInfo} - A promise that resolves with the user information.
     *
     * @example
     * ```
     * auth.getUserInfo().then((response) => {
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
    public getUserInfo(): Promise<UserInfo> {
        if (this._storage === Storage.WebWorker) {
            return this._client.getUserInfo();
        }

        return Promise.resolve(getUserInfoUtil(this._authConfig));
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
     * @param {string} fidp - Specifies the FIDP parameter
     * to direct the user directly to the IdP's sign-in page instead of the Single-Sign-On page.
     *
     * @return {Promise<UserInfo>} - A promise that resolves with the user information.
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
    public async signIn(fidp?: string): Promise<UserInfo> {
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

        if (this._storage === Storage.WebWorker) {
            return this._client
                .signIn(fidp)
                .then((response) => {
                    if (this._onSignInCallback) {
                        if (response.allowedScopes || response.displayName || response.email || response.username) {
                            this._onSignInCallback(response);
                        }
                    }

                    return Promise.resolve(response);
                })
                .catch((error) => {
                    return Promise.reject(error);
                });
        }

        return handleSignIn(this._authConfig, fidp)
            .then(() => {
                if (this._onSignInCallback) {
                    const userInfo = getUserInfoUtil(this._authConfig);
                    if (userInfo.allowedScopes || userInfo.displayName || userInfo.email || userInfo.username) {
                        this._onSignInCallback(getUserInfoUtil(this._authConfig));
                    }
                }

                return Promise.resolve(getUserInfoUtil(this._authConfig));
            })
            .catch((error) => {
                return Promise.reject(error);
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
    public async signOut(): Promise<boolean> {
        if (this._storage === Storage.WebWorker) {
            return this._client
                .signOut()
                .then((response) => {
                    return Promise.resolve(response);
                })
                .catch((error) => {
                    return Promise.reject(error);
                });
        }

        return handleSignOut(this._authConfig)
            .then((response) => {
                return Promise.resolve(response);
            })
            .catch((error) => {
                return Promise.reject(error);
            });
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
        if (this._storage === Storage.WebWorker) {
            return this._client.httpRequest(config);
        }

        return this._httpClient.request(config);
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
        if (this._storage === Storage.WebWorker) {
            return this._client.httpRequestAll(config);
        }

        const requests: Promise<HttpResponse<any>>[] = [];
        config.forEach((request) => {
            requests.push(this._httpClient.request(request));
        });

        return this._httpClient.all(requests);
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
    public async customGrant(
        requestParams: CustomGrantRequestParams
    ): Promise<boolean | HttpResponse<any> | SignInResponse> {
        if (!requestParams.id) {
            throw Error("No ID specified for the custom grant.");
        }

        if (this._storage === Storage.WebWorker) {
            return this._client
                .customGrant(requestParams)
                .then((response) => {
                    if (this._onCustomGrant.get(requestParams.id)) {
                        this._onCustomGrant.get(requestParams.id)(response);
                    }

                    return Promise.resolve(response);
                })
                .catch((error) => {
                    return Promise.reject(error);
                });
        }

        return customGrantUtil(requestParams, this._authConfig)
            .then((response) => {
                if (this._onCustomGrant.get(requestParams.id)) {
                    this._onCustomGrant.get(requestParams.id)(response);
                }

                return Promise.resolve(response);
            })
            .catch((error) => {
                return Promise.reject(error);
            });
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
    public async endUserSession(): Promise<boolean> {
        if (this._storage === Storage.WebWorker) {
            return this._client
                .endUserSession()
                .then((response) => {
                    if (this._onEndUserSession) {
                        this._onEndUserSession(response);

                        return Promise.resolve(response);
                    }
                })
                .catch((error) => {
                    return Promise.reject(error);
                });
        }

        return sendRevokeTokenRequest(this._authConfig, getSessionParameter(ACCESS_TOKEN, this._authConfig))
            .then((response) => {
                resetOPConfiguration(this._authConfig);
                endAuthenticatedSession(this._authConfig);

                if (this._onEndUserSession) {
                    this._onEndUserSession(response);

                    return Promise.resolve(true);
                }
            })
            .catch((error) => {
                return Promise.reject(error);
            });
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
    public async getServiceEndpoints(): Promise<ServiceResourcesType> {
        if (this._storage === Storage.WebWorker) {
            return this._client.getServiceEndpoints();
        }

        return Promise.resolve(getServiceEndpoints(this._authConfig));
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
            return this._httpClient;
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
    public getDecodedIDToken(): Promise<DecodedIdTokenPayloadInterface> {
        if (this._storage === Storage.WebWorker) {
            return this._client.getDecodedIDToken();
        }

        return Promise.resolve(getDecodedIDToken(this._authConfig));
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
    public getAccessToken(): Promise<string> {
        if (this._storage === Storage.WebWorker) {
            return Promise.reject("The access token cannot be obtained when the storage type is set to webWorker.");
        }

        return getAccessTokenUtil(this._authConfig);
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
    public refreshToken(): Promise<TokenResponseInterface> {
        if (this._storage === Storage.WebWorker) {
            return Promise.reject("The token is automatically refreshed when the storage type is set to webWorker.");
        }

        return sendRefreshTokenRequest(this._authConfig, getSessionParameter(REFRESH_TOKEN, this._authConfig));
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
                    if (isLoggedOut()) {
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
                        this._client.onHttpRequestError(callback);
                    }

                    this._onHttpRequestError = callback;
                    break;
                case Hooks.HttpRequestFinish:
                    if (this._storage === Storage.WebWorker) {
                        this._client.onHttpRequestFinish(callback);
                    }

                    this._onHttpRequestFinish = callback;
                    break;
                case Hooks.HttpRequestStart:
                    if (this._storage === Storage.WebWorker) {
                        this._client.onHttpRequestStart(callback);
                    }

                    this._onHttpRequestStart = callback;
                    break;
                case Hooks.HttpRequestSuccess:
                    if (this._storage === Storage.WebWorker) {
                        this._client.onHttpRequestSuccess(callback);
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
    public enableHttpHandler(): Promise<boolean> {
        if (this._storage === Storage.WebWorker) {
            return this._client.enableHttpHandler();
        } else {
            this._httpClient.enableHandler();

            return Promise.resolve(true);
        }
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
    public disableHttpHandler(): Promise<boolean> {
        if (this._storage === Storage.WebWorker) {
            return this._client.disableHttpHandler();
        } else {
            this._httpClient.disableHandler();

            return Promise.resolve(true);
        }
    }
}
