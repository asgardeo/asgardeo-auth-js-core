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
import {Storage} from "../constants";
import {
    ConfigInterface,
    HttpResponse,
    HttpError,
    HttpRequestConfig,
    MainThreadClientConfig
} from "../models";
import { LocalStore } from "../stores/local-store";
import { MemoryStore } from "../stores/memory-store";
import { SessionStore } from "../stores/session-store";
import { HttpClientInstance, HttpClient } from "../http-client";
import { SPAUtils } from "../utils/spa-utils";
import {
    Store,
    AsgardeoAuthClient,
    ResponseMode,
    AUTHORIZATION_CODE,
    SESSION_STATE,
    PKCE_CODE_VERIFIER,
    SignInConfig,
    BasicUserInfo,
    CustomGrantConfig,
    TokenResponse,
    DecodedIdTokenPayload,
    OIDCEndpoints,
    AuthClientConfig
} from "../core";

const initiateStore = (store: Storage): Store => {
    switch (store) {
        case Storage.LocalStorage:
            return new LocalStore();
        case Storage.SessionStorage:
            return new SessionStore();
        case Storage.MainThreadMemory:
            return new MemoryStore();
        default:
            return new SessionStore();
    }
};

export const MainThreadClient = (config: AuthClientConfig<MainThreadClientConfig>): any => {
    const _store: Store = initiateStore(config.storage);
    const _authenticationClient = new AsgardeoAuthClient(config, _store);
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
        return _httpClient.request(config);
    };

    const httpRequestAll = (config: HttpRequestConfig[]): Promise<HttpResponse[]> => {
        const requests: Promise<HttpResponse<any>>[] = [];
        config.forEach((request) => {
            requests.push(_httpClient.request(request));
        });

        return _httpClient.all(requests);
    };

    const getHttpClient = (): HttpClientInstance => {
        return _httpClient;
    };

    const enableHttpHandler = (): void => {
        _httpClient.enableHandler();
    };

    const disableHttpHandler = (): void => {
        _httpClient.disableHandler();
    };

    const signIn = (
        config?: SignInConfig,
        authorizationCode?: string,
        sessionState?: string
    ): Promise<BasicUserInfo> => {
        if (_authenticationClient.isAuthenticated()) {
            return Promise.resolve(_authenticationClient.getBasicUserInfo());
        }

        let resolvedAuthorizationCode: string;
        let resolvedSessionState: string;

        if (config?.responseMode === ResponseMode.formPost && authorizationCode && sessionState) {
            resolvedAuthorizationCode = authorizationCode;
            resolvedSessionState = sessionState;
        } else {
            resolvedAuthorizationCode = new URL(window.location.href).searchParams.get(AUTHORIZATION_CODE);
            resolvedSessionState = new URL(window.location.href).searchParams.get(SESSION_STATE);
        }

        SPAUtils.removeAuthorizationCode();

        if (resolvedAuthorizationCode && resolvedSessionState) {
            if (config.storage === Storage.MainThreadMemory) {
                const pkce = SPAUtils.getPKCE();

                _dataLayer.setTemporaryDataParameter(PKCE_CODE_VERIFIER, pkce);
            }

            return _authenticationClient
                .sendTokenRequest(resolvedAuthorizationCode, resolvedSessionState)
                .then(() => {
                    if (config.storage === Storage.MainThreadMemory) {
                        SPAUtils.setSignOutURL(_authenticationClient.getSignOutURL());
                    }

                    return _authenticationClient.getBasicUserInfo();
                })
                .catch((error) => {
                    return Promise.reject(error);
                });
        }

        return _authenticationClient.getAuthorizationURL(config).then((url: string) => {
            if (config.storage === Storage.MainThreadMemory) {
                SPAUtils.setPKCE( _dataLayer.getTemporaryDataParameter(PKCE_CODE_VERIFIER) as string);
            }

            location.href = url;

            return Promise.resolve({
                allowedScopes: "",
                displayName: "",
                email: "",
                sessionState: "",
                tenantDomain: "",
                username: ""
            });
        });
    };

    const signOut = () => {
        if (_authenticationClient.isAuthenticated()) {
            location.href = _authenticationClient.signOut();
        } else {
            location.href = SPAUtils.getSignOutURL();
        }
    };

    const customGrant = (config: CustomGrantConfig): Promise<BasicUserInfo | HttpResponse> => {
        return _authenticationClient
            .sendCustomGrantRequest(config)
            .then((response: HttpResponse | TokenResponse) => {
                if (config.returnsSession) {
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
                return _authenticationClient.getBasicUserInfo();
            })
            .catch((error) => {
                return Promise.reject(error);
            });
    };

    const revokeAccessToken = (): Promise<boolean> => {
        return _authenticationClient
            .revokeToken()
            .then(() => Promise.resolve(true))
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
    };

    return {
        customGrant,
        getAccessToken,
        getDecodedIDToken,
        getOIDCServiceEndpoints,
        getUserInfo,
        isAuthenticated,
        refreshToken,
        revokeAccessToken,
        setHttpRequestError,
        setHttpRequestFinish,
        setHttpRequestStartCallback,
        setHttpRequestSuccessCallback,
        signIn,
        signOut,
        httpRequest,
        httpRequestAll,
        enableHttpHandler,
        disableHttpHandler,
        getHttpClient
    };
};
