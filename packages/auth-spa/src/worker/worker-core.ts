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
    AsgardeoAuthClient,
    AuthClientConfig,
    AuthorizationURLParams,
    BasicUserInfo,
    CustomGrantConfig,
    DecodedIDTokenPayload,
    OIDCEndpoints,
    SESSION_STATE,
    Store,
    TokenResponse
} from "@asgardeo/auth-js";
import { AsgardeoSPAException } from "../exception";
import { SPAHelper } from "../helpers";
import { HttpClient, HttpClientInstance } from "../http-client";
import {
    AuthorizationResponse,
    HttpError,
    HttpRequestConfig,
    HttpResponse,
    WebWorkerClientConfig,
    WebWorkerCoreInterface
} from "../models";
import { MemoryStore } from "../stores";

export const WebWorkerCore = async (
    config: AuthClientConfig<WebWorkerClientConfig>
): Promise<WebWorkerCoreInterface> => {
    const _store: Store = new MemoryStore();
    const _authenticationClient = new AsgardeoAuthClient<WebWorkerClientConfig>(_store);
    await _authenticationClient.initialize(config);

    const _spaHelper = new SPAHelper<WebWorkerClientConfig>(_authenticationClient);
    const _dataLayer = _authenticationClient.getDataLayer();

    let _onHttpRequestStart: () => void;
    let _onHttpRequestSuccess: (response: HttpResponse) => void;
    let _onHttpRequestFinish: () => void;
    let _onHttpRequestError: (error: HttpError) => void;
    const _httpClient: HttpClientInstance = HttpClient.getInstance();

    const attachToken = async (request: HttpRequestConfig): Promise<void> => {
        request.headers = {
            ...request.headers,
            Authorization: `Bearer ${await _authenticationClient.getAccessToken()}`
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

    const httpRequest = async (config: HttpRequestConfig): Promise<HttpResponse> => {
        let matches = false;
        (await _dataLayer.getConfigData()).resourceServerURLs.forEach((baseUrl) => {
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
                        return _authenticationClient
                            .refreshAccessToken()
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
                            .catch((refreshError) => {
                                return Promise.reject(
                                    new AsgardeoSPAException(
                                        "WORKER_CORE-HR-ES01",
                                        "worker-core",
                                        "httpRequest",
                                        null,
                                        null,
                                        refreshError
                                    )
                                );
                            });
                    }

                    return Promise.reject(error);
                });
        } else {
            return Promise.reject(
                new AsgardeoSPAException(
                    "WORKER_CORE-HR-IV02",
                    "worker-core",
                    "httpRequest",
                    "Request to the provided endpoint is prohibited.",
                    "Requests can only be sent to resource servers specified by the `resourceServerURLs`" +
                        " attribute while initializing the SDK. The specified endpoint in this request " +
                        "cannot be found among the `resourceServerURLs`"
                )
            );
        }
    };

    const httpRequestAll = async (configs: HttpRequestConfig[]): Promise<HttpResponse[]> => {
        let matches = false;
        (await _dataLayer.getConfigData()).resourceServerURLs.forEach((baseUrl) => {
            if (configs.every((config) => config.url.startsWith(baseUrl))) {
                matches = true;
            }
        });

        const requests: Promise<HttpResponse<any>>[] = [];
        configs.forEach((request) => {
            requests.push(_httpClient.request(request));
        });
        if (matches) {
            return _httpClient
                .all(requests)
                .then((responses: HttpResponse[]) => {
                    return Promise.resolve(responses);
                })
                .catch((error: HttpError) => {
                    if (error?.response?.status === 401) {
                        return _authenticationClient
                            .refreshAccessToken()
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
                            .catch((refreshError) => {
                                return Promise.reject(
                                    new AsgardeoSPAException(
                                        "WORKER_CORE-HRA-ES01",
                                        "worker-core",
                                        "httpRequestAll",
                                        null,
                                        null,
                                        refreshError
                                    )
                                );
                            });
                    }

                    return Promise.reject(error);
                });
        } else {
            return Promise.reject(
                new AsgardeoSPAException(
                    "WORKER_CORE-HRA-IV02",
                    "worker-core",
                    "httpRequest",
                    "Request to the provided endpoint is prohibited.",
                    "Requests can only be sent to resource servers specified by the `resourceServerURLs`" +
                        " attribute while initializing the SDK. The specified endpoint in this request " +
                        "cannot be found among the `resourceServerURLs`"
                )
            );
        }
    };

    const enableHttpHandler = (): void => {
        _httpClient.enableHandler();
    };

    const disableHttpHandler = (): void => {
        _httpClient.disableHandler();
    };

    const getAuthorizationURL = async (params?: AuthorizationURLParams): Promise<AuthorizationResponse> => {
        return _authenticationClient.getAuthorizationURL(params).then(async (url: string) => {
            return { authorizationURL: url, pkce: (await _authenticationClient.getPKCECode()) as string };
        });
    };

    const startAutoRefreshToken = async (): Promise<void> => {
        _spaHelper.clearRefreshTokenTimeout();
        _spaHelper.refreshAccessTokenAutomatically();

        return;
    };

    const requestAccessToken = async (
        authorizationCode?: string,
        sessionState?: string,
        pkce?: string
    ): Promise<BasicUserInfo> => {
        if (pkce) {
            await _authenticationClient.setPKCECode(pkce);
        }

        if (authorizationCode && sessionState) {
            return _authenticationClient
                .requestAccessToken(authorizationCode, sessionState)
                .then(() => {
                    _spaHelper.refreshAccessTokenAutomatically();

                    return _authenticationClient.getBasicUserInfo();
                })
                .catch((error) => {
                    return Promise.reject(error);
                });
        }

        return Promise.reject(
            new AsgardeoSPAException(
                "WORKER_CORE-RAT1-NF01",
                "worker-core",
                "requestAccessToken",
                "No authorization code found.",
                "No authorization code and session state found."
            )
        );
    };

    const signOut = async (): Promise<string> => {
        _spaHelper.clearRefreshTokenTimeout();

        return await _authenticationClient.signOut();
    };

    const getSignOutURL = async (): Promise<string> => {
        return await _authenticationClient.getSignOutURL();
    };

    const requestCustomGrant = async (config: CustomGrantConfig): Promise<BasicUserInfo | HttpResponse> => {
        return _authenticationClient
            .requestCustomGrant(config)
            .then(async (response: HttpResponse | TokenResponse) => {
                if (config.returnsSession) {
                    _spaHelper.refreshAccessTokenAutomatically();

                    return _authenticationClient.getBasicUserInfo();
                } else {
                    return response as HttpResponse;
                }
            })
            .catch((error) => {
                return Promise.reject(error);
            });
    };

    const refreshAccessToken = (): Promise<BasicUserInfo> => {
        return _authenticationClient
            .refreshAccessToken()
            .then(() => {
                _spaHelper.refreshAccessTokenAutomatically();

                return _authenticationClient.getBasicUserInfo();
            })
            .catch((error) => {
                return Promise.reject(error);
            });
    };

    const revokeAccessToken = (): Promise<boolean> => {
        return _authenticationClient
            .revokeAccessToken()
            .then(() => {
                _spaHelper.clearRefreshTokenTimeout();

                return Promise.resolve(true);
            })
            .catch((error) => Promise.reject(error));
    };

    const getBasicUserInfo = async (): Promise<BasicUserInfo> => {
        return _authenticationClient.getBasicUserInfo();
    };

    const getDecodedIDToken = async (): Promise<DecodedIDTokenPayload> => {
        return _authenticationClient.getDecodedIDToken();
    };

    const getOIDCServiceEndpoints = async (): Promise<OIDCEndpoints> => {
        return _authenticationClient.getOIDCServiceEndpoints();
    };

    const getAccessToken = (): Promise<string> => {
        return _authenticationClient.getAccessToken();
    };

    const isAuthenticated = (): Promise<boolean> => {
        return _authenticationClient.isAuthenticated();
    };

    const setSessionState = async (sessionState: string): Promise<void> => {
        await _dataLayer.setSessionDataParameter(SESSION_STATE, sessionState);

        return;
    };

    const updateConfig = async (config: Partial<AuthClientConfig<WebWorkerClientConfig>>): Promise<void> => {
        await _authenticationClient.updateConfig(config);

        return;
    };

    return {
        disableHttpHandler,
        enableHttpHandler,
        getAccessToken,
        getAuthorizationURL,
        getBasicUserInfo,
        getDecodedIDToken,
        getOIDCServiceEndpoints,
        getSignOutURL,
        httpRequest,
        httpRequestAll,
        isAuthenticated,
        refreshAccessToken,
        requestAccessToken,
        requestCustomGrant,
        revokeAccessToken,
        setHttpRequestError,
        setHttpRequestFinish,
        setHttpRequestStartCallback,
        setHttpRequestSuccessCallback,
        setSessionState,
        signOut,
        startAutoRefreshToken,
        updateConfig
    };
};
