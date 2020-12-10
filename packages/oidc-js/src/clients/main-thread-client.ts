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

import { Store } from "../core/models/store";
import {
    ConfigInterface,
    UserInfo,
    GetAuthorizationURLParameter,
    CustomGrantRequestParams,
    TokenResponseInterface,
    DecodedIdTokenPayloadInterface,
    OIDCEndpointConstantsInterface
} from "../models";
import { Storage, ResponseMode, AUTHORIZATION_CODE, SESSION_STATE } from "../constants";
import { LocalStore } from "../stores/local-store";
import { SessionStore } from "../stores/session-store";
import { MemoryStore } from "../stores/memory-store";
import { AuthenticationClient } from "../core/authentication-client";
import { AxiosResponse } from "axios";

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

const MainThreadClient = (config: ConfigInterface) => {
    const _store: Store = initiateStore(config.storage);
    const _authenticationClient = new AuthenticationClient(config, _store);

    const signIn = (
        params?: GetAuthorizationURLParameter,
        authorizationCode?: string,
        sessionState?: string
    ): Promise<UserInfo> => {
        if (_store.getSessionData().access_token) {
            return Promise.resolve(_authenticationClient.getUserInfo());
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

        if (resolvedAuthorizationCode && resolvedSessionState) {
            return _authenticationClient
                .sendTokenRequest(resolvedAuthorizationCode, resolvedSessionState)
                .then(() => {
                    return _authenticationClient.getUserInfo();
                })
                .catch((error) => {
                    return Promise.reject(error);
                });
        }

        location.href = _authenticationClient.getAuthorizationURL();

        return Promise.resolve({
            allowedScopes: "",
            displayName: "",
            email: "",
            sessionState: "",
            tenantDomain: "",
            username: ""
        });
    };

    const signOut = () => {
        location.href = _authenticationClient.getSignOutURL();
    };

    const sendCustomGrantRequest = (config: CustomGrantRequestParams): Promise<UserInfo | AxiosResponse> => {
        return _authenticationClient
            .sendCustomGrantRequest(config)
            .then((response: AxiosResponse | TokenResponseInterface) => {
                if (config.returnsSession) {
                    return _authenticationClient.getUserInfo();
                } else {
                    return response as AxiosResponse;
                }
            })
            .catch((error) => {
                return Promise.reject(error);
            });
    };

    const sendRefreshTokenRequest = (): Promise<UserInfo> => {
        return _authenticationClient
            .refreshToken()
            .then(() => {
                return _authenticationClient.getUserInfo();
            })
            .catch((error) => {
                return Promise.reject(error);
            });
    };

    const sendRevokeTokenRequest = (): Promise<boolean> => {
        return _authenticationClient
            .revokeToken()
            .then(() => Promise.resolve(true))
            .catch((error) => Promise.reject(error));
    };

    const getUserInfo = (): UserInfo => {
        return _authenticationClient.getUserInfo();
    };

    const getDecodedIDToken = (): DecodedIdTokenPayloadInterface => {
        return _authenticationClient.getDecodedIDToken();
    };

    const getOIDCServiceEndpoints = (): OIDCEndpointConstantsInterface => {
        return _authenticationClient.getOIDCEndpoints();
    };
};
