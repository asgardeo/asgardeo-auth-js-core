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

import { AsgardeoAuthClient, Store, AuthorizationURLParams, BasicUserInfo, CustomGrantConfig, TokenResponse, DecodedIdTokenPayload, OIDCEndpoints, AuthClientConfig } from "../core";
import {
    GetAuthorizationURLInterface,
    HttpResponse,
    HttpError,
    HttpRequestConfig,
    WebWorkerClientConfig,
    WebWorkerCoreInterface
} from "../models";
import { LocalStore } from "../stores/local-store";
import { MemoryStore } from "../stores";
import { SessionStore } from "../stores/session-store";
import { AuthenticationUtils } from "../core/utils/authentication-utils";
import { promises } from "dns";
import { HttpClientInstance, HttpClient } from "../http-client";
import { SPAHelper } from "../helpers";


export const WebWorkerCore = (config: AuthClientConfig<WebWorkerClientConfig>): WebWorkerCoreInterface => {
    const _store: Store = new MemoryStore();
    const _authenticationClient = new AsgardeoAuthClient<WebWorkerClientConfig>(config, _store);
    const _spaHelper = new SPAHelper<WebWorkerClientConfig>(_authenticationClient);
    const _dataLayer = _authenticationClient.getDataLayer();

    let _onHttpRequestStart: () => void;
    let _onHttpRequestSuccess: (response: HttpResponse) => void;
    let _onHttpRequestFinish: () => void;
    let _onHttpRequestError: (error: HttpError) => void;
    const _httpClient: HttpClientInstance = HttpClient.getInstance();

    const attachToken = (request: HttpRequestConfig): void => {
        request.headers = {
            ...request.headers,
            Authorization: `Bearer ${_authenticationClient.getAccessToken()}`
        };
    };

    _httpClient.init(
        true,
        attachToken,
        _onHttpRequestStart,
        _onHttpRequestSuccess,
        _onHttpRequestError,
        _onHttpRequestFinish
    );

    const setHttpRequestStartCallback = (callback: () => void): void => {
        _onHttpRequestStart = callback;
    };

    const setHttpRequestSuccessCallback = (callback: (response: HttpResponse) => void): void => {
        _onHttpRequestSuccess = callback;
    };

    const setHttpRequestFinish = (callback: () => void): void => {
        _onHttpRequestFinish = callback;
    };

    const setHttpRequestError = (callback: (error: HttpError) => void): void => {
        _onHttpRequestError = callback;
    };

    const httpRequest = (config: HttpRequestConfig): Promise<HttpResponse> => {
         let matches = false;
         _dataLayer.getConfigData().resourceServerURLs.forEach((baseUrl) => {
             if (config?.url?.startsWith(baseUrl)) {
                 matches = true;
             }
         });

        if (matches) {
            return _httpClient
                .request(config)
                .then((response: HttpResponse) => {
                    return Promise.resolve(response);
                })
                .catch((error: HttpError) => {
                    if (error?.response?.status === 401) {
                        return _authenticationClient.refreshToken()
                            .then(() => {
                                return _httpClient
                                    .request(config)
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

    const httpRequestAll = (configs: HttpRequestConfig[]): Promise<HttpResponse[]> => {
        let matches = false;
        _dataLayer.getConfigData().resourceServerURLs.forEach((baseUrl) => {
            if (configs.every((config) => config.url.startsWith(baseUrl))) {
                matches = true;
            }
        });

        const requests: Promise<HttpResponse<any>>[] = [];
        configs.forEach((request) => {
            requests.push(_httpClient.request(request));
        });
 if (matches) {
            return _httpClient.all(requests)
                .then((responses: HttpResponse[]) => {
                    return Promise.resolve(responses);
                })
                .catch((error: HttpError) => {
                    if (error?.response?.status === 401) {

                        return _authenticationClient.refreshToken()
                            .then(() => {
                                return _httpClient
                                    .all(requests)
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


    const enableHttpHandler = (): void => {
        _httpClient.enableHandler();
    };

    const disableHttpHandler = (): void => {
        _httpClient.disableHandler();
    };

    const getAuthorizationURL = (
        params?: AuthorizationURLParams
    ): Promise<GetAuthorizationURLInterface> => {
        return _authenticationClient.getAuthorizationURL(params).then((url: string) => {
            return { authorizationCode: url, pkce: _authenticationClient.getPKCECode() as string };
        });
    };

    const sendTokenRequest = (
        authorizationCode?: string,
        sessionState?: string,
        pkce?: string
    ): Promise<BasicUserInfo> => {

        if (pkce) {
            _authenticationClient.setPKCECode(pkce);
        }

        if (authorizationCode && sessionState) {
            return _authenticationClient
                .sendTokenRequest(authorizationCode, sessionState)
                .then(() => {
                    _spaHelper.refreshTokenAutomatically();

                    return _authenticationClient.getBasicUserInfo();
                })
                .catch((error) => {
                    return Promise.reject(error);
                });
        }

        return Promise.reject("No auth code received");
    };

    const signOut = (): string => {
        console.log("signout worker method");
        _spaHelper.clearRefreshTokenTimeout();

        return _authenticationClient.signOut();
    };

    const getSignOutURL = (): string => {
        return _authenticationClient.getSignOutURL();
    }

    const customGrant = (config: CustomGrantConfig): Promise<BasicUserInfo | HttpResponse> => {
        return _authenticationClient
            .sendCustomGrantRequest(config)
            .then((response: HttpResponse | TokenResponse) => {
                if (config.returnsSession) {
                    _spaHelper.refreshTokenAutomatically();

                    return _authenticationClient.getBasicUserInfo();
                } else {
                    return response as HttpResponse;
                }
            })
            .catch((error) => {
                return Promise.reject(error);
            });
    };

    const refreshToken = (): Promise<BasicUserInfo> => {
        return _authenticationClient
            .refreshToken()
            .then(() => {
                _spaHelper.refreshTokenAutomatically();

                return _authenticationClient.getBasicUserInfo();
            })
            .catch((error) => {
                return Promise.reject(error);
            });
    };

    const revokeToken = (): Promise<boolean> => {
        return _authenticationClient
            .revokeToken()
            .then(() => {
                _spaHelper.clearRefreshTokenTimeout();

                return Promise.resolve(true);
            })
            .catch((error) => Promise.reject(error));
    };

    const getUserInfo = (): BasicUserInfo => {
        return _authenticationClient.getBasicUserInfo();
    };

    const getDecodedIDToken = (): DecodedIdTokenPayload => {
        return _authenticationClient.getDecodedIDToken();
    };

    const getOIDCServiceEndpoints = (): OIDCEndpoints => {
        return _authenticationClient.getOIDCEndpoints();
    };

    const getAccessToken = (): string => {
        return _authenticationClient.getAccessToken();
    };

    const isAuthenticated = (): boolean => {
        return _authenticationClient.isAuthenticated();
    }

    return {
        customGrant,
        getAccessToken,
        getAuthorizationURL,
        getDecodedIDToken,
        getOIDCServiceEndpoints,
        getUserInfo,
        refreshToken,
        revokeToken,
        signOut,
        isAuthenticated,
        httpRequest,
        httpRequestAll,
        enableHttpHandler,
        disableHttpHandler,
        sendTokenRequest,
        setHttpRequestError,
        setHttpRequestFinish,
        setHttpRequestStartCallback,
        setHttpRequestSuccessCallback,
        getSignOutURL
    };
};
