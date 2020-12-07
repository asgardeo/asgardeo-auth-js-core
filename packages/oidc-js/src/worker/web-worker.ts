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

import axios from "axios";
import {
    ACCESS_TOKEN,
    AUTHORIZATION_CODE,
    DISPLAY_NAME,
    EMAIL,
    ID_TOKEN,
    PKCE_CODE_VERIFIER,
    SCOPE,
    SESSION_STATE,
    SIGNED_IN,
    SIGN_OUT_REDIRECT_URL,
    TENANT_DOMAIN,
    USERNAME
} from "../constants";
import { HttpClient, HttpClientInstance } from "../http-client";
import {
    CustomGrantRequestParams,
    DecodedIdTokenPayloadInterface,
    HttpError,
    HttpPromise,
    HttpRequestConfig,
    HttpResponse,
    ServiceResourcesType,
    SessionData,
    SignInResponse,
    SignInResponseWorker,
    UserInfo,
    WebWorkerClientConfigInterface,
    WebWorkerConfigInterface,
    WebWorkerInterface,
    WebWorkerSingletonInterface
} from "../models";
import {
    customGrant as customGrantUtil,
    endAuthenticatedSession,
    getDecodedIDToken as getDecodedIDTokenUtil,
    getEndSessionEndpoint,
    getServiceEndpoints as getServiceEndpointsUtil,
    getSessionParameter,
    getUserInfo as getUserInfoUtil,
    handleSignIn,
    handleSignOut,
    resetOPConfiguration,
    sendRefreshTokenRequest as sendRefreshTokenRequestUtil,
    sendRevokeTokenRequest as sendRevokeTokenRequestUtil
} from "../utils";

export const WebWorker: WebWorkerSingletonInterface = ((): WebWorkerSingletonInterface => {
    /**
     * Values to be set when initializing the library.
     */
    let authConfig: WebWorkerConfigInterface;

    let httpClient: HttpClientInstance;

    let instance: WebWorkerInterface;

    const session: SessionData = new Map<string, string>();

    /**
     * Returns if the user has signed in or not.
     *
     * @returns {boolean} Signed in or not.
     */
    const isSignedIn = (): boolean => {
        return !!session.get(ACCESS_TOKEN);
    };

    /**
     * Checks if an access token exists.
     *
     * @returns {boolean} If the access token exists or not.
     */
    const doesTokenExist = (): boolean => {
        if (session.get(ACCESS_TOKEN)) {
            return true;
        }

        return false;
    };

    /**
     * Sends a sign in request.
     *
     * @returns {Promise<SignInResponse>} A promise that resolves with the Sign In response.
     */
    const signIn = (fidp?: string): Promise<SignInResponseWorker> => {
        return handleSignIn(authConfig, fidp)
            .then((response) => {
                if (response.type === SIGNED_IN) {
                    const logoutEndpoint = getEndSessionEndpoint(authConfig);

                    if (!logoutEndpoint || logoutEndpoint.trim().length === 0) {
                        return Promise.reject(new Error("No logout endpoint found in the session."));
                    }

                    const idToken = getSessionParameter(ID_TOKEN, authConfig);

                    if (!idToken || idToken.trim().length === 0) {
                        return Promise.reject(new Error("Invalid id_token found in the session."));
                    }

                    const redirectURL = getSessionParameter(SIGN_OUT_REDIRECT_URL, authConfig);

                    if (!redirectURL || redirectURL.trim().length === 0) {
                        return Promise.reject(new Error("No callback URL found in the session."));
                    }

                    const logoutCallback =
                        `${logoutEndpoint}?` + `id_token_hint=${idToken}` + `&post_logout_redirect_uri=${redirectURL}`;

                    return Promise.resolve({
                        data: {
                            allowedScopes: session.get(SCOPE),
                            displayName: session.get(DISPLAY_NAME),
                            email: session.get(EMAIL),
                            logoutUrl: logoutCallback,
                            sessionState: session.get(SESSION_STATE),
                            tenantDomain: session.get(TENANT_DOMAIN),
                            username: session.get(USERNAME)
                        },
                        type: response.type
                    });
                }

                return Promise.resolve(response);
            })
            .catch((error) => {
                return Promise.reject(error);
            });
    };

    /**
     * Refreshes the token.
     *
     * @returns {Promise<boolean>} A promise that resolves with `true` if refreshing is successful.
     */
    const refreshAccessToken = (): Promise<boolean> => {
        return sendRefreshTokenRequestUtil(authConfig, session.get(ACCESS_TOKEN)).then(() => {
            return Promise.resolve(true);
        }).catch((error) => {
            return Promise.reject(error);
        });
    };

    /**
     * Signs out.
     *
     * @returns {Promise<boolean>} A promise that resolves with `true` if sign out is successful.
     */
    const signOut = (): Promise<string> => {
        return handleSignOut(authConfig);
    };

    /**
     * Revokes the token.
     *
     * @returns {Promise<boolean>} A promise that resolves with `true` if revoking is successful.
     */
    const endUserSession = (): Promise<boolean> => {
        return sendRevokeTokenRequestUtil(authConfig, session.get(ACCESS_TOKEN)).then(() => {
            endAuthenticatedSession(authConfig);
            resetOPConfiguration(authConfig);

            return Promise.resolve(true);
        }).catch(error => {
            return Promise.reject(error);
        });
    };

    /**
     * Saves the passed authorization code on the session
     *
     * @param {string} authCode - The authorization code.
     * @param {string} sessionState - Session state.
     * @param {string} pkce - PKCE code.
     */
    const setAuthCode = (authCode: string, sessionState: string, pkce: string): void => {
        authCode && session.set(AUTHORIZATION_CODE, authCode);
        sessionState && session.set(SESSION_STATE, sessionState);
        session.set(PKCE_CODE_VERIFIER, pkce);
    };

    /**
     * Makes api calls.
     *
     * @param {HttpRequestConfig} config API request data.
     *
     * @returns {HttpResponse} A promise that resolves with the response.
     */
    const httpRequest = (config: HttpRequestConfig): Promise<HttpResponse> => {
        let matches = false;
        authConfig.resourceServerURLs.forEach((baseUrl) => {
            if (config?.url?.startsWith(baseUrl)) {
                matches = true;
            }
        });

        if (matches) {
            return httpClient.request(config)
                .then((response: HttpResponse) => {
                    return Promise.resolve(response);
                })
                .catch((error: HttpError) => {
                    if (error?.response?.status === 401) {

                        return refreshAccessToken()
                            .then(() => {
                                return httpClient(config)
                                    .then((response) => {
                                        return Promise.resolve(response);
                                    })
                                    .catch((error) => {
                                        return Promise.reject(error);
                                    });
                            })
                            .catch(() => {
                                return Promise.reject("An error occurred while refreshing the access token. " +
                                    "The access token is no more valid and re-authentication is required.");
                            });
                    }

                    return Promise.reject(error);
                });
        } else {
            return Promise.reject("The provided URL is illegal.");
        }
    };

    /**
     * Makes multiple api calls. Wraps `axios.spread`.
     *
     * @param {HttpRequestConfig[]} configs - API request data.
     *
     * @returns {HttpResponse[]} A promise that resolves with the response.
     */
    const httpRequestAll = (configs: HttpRequestConfig[]): Promise<HttpResponse[]> => {
        let matches = false;
        authConfig.resourceServerURLs.forEach((baseUrl) => {
            if (configs.every((config) => config.url.startsWith(baseUrl))) {
                matches = true;
            }
        });

        const httpRequests: HttpPromise[] = configs.map((config: HttpRequestConfig) => {
            return httpClient.request(config);
        });

        if (matches) {
            return axios
                .all(httpRequests)
                .then((responses: HttpResponse[]) => {
                    return Promise.resolve(responses);
                })
                .catch((error: HttpError) => {
                    if (error?.response?.status === 401) {

                        return refreshAccessToken()
                            .then(() => {
                                return axios
                                    .all(httpRequests)
                                    .then((response) => {
                                        return Promise.resolve(response);
                                    })
                                    .catch((error) => {
                                        return Promise.reject(error);
                                    });
                            })
                            .catch(() => {
                                return Promise.reject(
                                    "An error occurred while refreshing the access token. " +
                                        "The access token is no more valid and re-authentication is required."
                                );
                            });
                    }

                    return Promise.reject(error);
                });
        } else {
            return Promise.reject("The provided URL is illegal.");
        }
    };

    const customGrant = (
        requestParams: CustomGrantRequestParams
    ): Promise<SignInResponse | boolean | HttpResponse> => {
        return customGrantUtil(requestParams, authConfig);
    };

    const getUserInfo = (): UserInfo => {
        return getUserInfoUtil(authConfig);
    };

    const getServiceEndpoints = (): Promise<ServiceResourcesType> => {
        return Promise.resolve(getServiceEndpointsUtil(authConfig));
    };

    const getDecodedIDToken = (): DecodedIdTokenPayloadInterface => {
        return getDecodedIDTokenUtil(authConfig);
    };

    /**
     * @constructor
     *
     * Constructor function that returns an object containing all the public methods.
     *
     * @param {ConfigInterface} config Configuration data.
     *
     * @returns {WebWorkerInterface} Returns the object containing
     */
    function Constructor(config: WebWorkerClientConfigInterface): WebWorkerInterface {
        authConfig = { ...config };
        session.clear();
        authConfig.session = session;

        if (authConfig.authorizationCode) {
            session.set(AUTHORIZATION_CODE, authConfig.authorizationCode);
        }

        if (authConfig.sessionState) {
            session.set(SESSION_STATE, authConfig.sessionState);
        }

        httpClient = HttpClient.getInstance();

        const startCallback = (request: HttpRequestConfig): void => {
            request.headers = {
                ...request.headers,
                Authorization: `Bearer ${ session?.get(ACCESS_TOKEN) }`
            };

            config.httpClient?.requestStartCallback && config.httpClient?.requestStartCallback();

        };

        httpClient.init(
            true,
            startCallback,
            config.httpClient?.requestSuccessCallback ?? null,
            config.httpClient?.requestErrorCallback ?? null,
            config.httpClient?.requestFinishCallback ?? null
        );

        return {
            customGrant,
            doesTokenExist,
            endUserSession,
            getDecodedIDToken,
            getServiceEndpoints,
            getUserInfo,
            httpRequest,
            httpRequestAll,
            isSignedIn,
            refreshAccessToken,
            setAuthCode,
            signIn,
            signOut
        };
    }

    return {
        getInstance: (config: WebWorkerClientConfigInterface): WebWorkerInterface => {
            if (instance) {
                return instance;
            } else {
                instance = Constructor(config);

                return instance;
            }
        }
    };
})();
