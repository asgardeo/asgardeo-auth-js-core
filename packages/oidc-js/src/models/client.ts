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

import { Storage } from "../constants";
import {
    AuthClientConfig,
    BasicUserInfo,
    CustomGrantConfig,
    DecodedIdTokenPayload,
    OIDCEndpoints,
    OIDCProviderMetaData,
    SignInConfig
} from "../core";
import { HttpClientInstance } from "../http-client";
import { HttpError, HttpRequestConfig, HttpResponse } from "../models";

/**
 * SDK Client config parameters.
 */
export interface MainThreadClientConfig {
    storage?: Storage.SessionStorage | Storage.LocalStorage | Storage.BrowserMemory;
}

export interface WebWorkerClientConfig {
    resourceServerURLs: string[];
    storage: Storage.WebWorker;
    requestTimeout?: number;
}

export type Config = MainThreadClientConfig | WebWorkerClientConfig;

export interface MainThreadClientInterface {
    setHttpRequestStartCallback(callback: () => void): void;
    setHttpRequestSuccessCallback(callback: (response: HttpResponse) => void): void;
    setHttpRequestFinishCallback(callback: () => void): void;
    setHttpRequestErrorCallback(callback: (error: HttpError) => void): void;
    httpRequest(config: HttpRequestConfig): Promise<HttpResponse>;
    httpRequestAll(config: HttpRequestConfig[]): Promise<HttpResponse[]>;
    getHttpClient(): HttpClientInstance;
    enableHttpHandler(): boolean;
    disableHttpHandler(): boolean;
    signIn(
        config?: SignInConfig,
        authorizationCode?: string,
        sessionState?: string,
        signInRedirectURL?: string
    ): Promise<BasicUserInfo>;
    signOut(signOutRedirectURL?: string): boolean;
    requestCustomGrant(config: CustomGrantConfig): Promise<BasicUserInfo | HttpResponse>;
    refreshAccessToken(): Promise<BasicUserInfo>;
    revokeAccessToken(): Promise<boolean>;
    getBasicUserInfo(): BasicUserInfo;
    getDecodedIDToken(): DecodedIdTokenPayload;
    getOIDCServiceEndpoints(): OIDCEndpoints;
    getAccessToken(): string;
    isAuthenticated(): boolean;
    updateConfig(config: Partial<AuthClientConfig<MainThreadClientConfig>>): void;
}

export interface WebWorkerClientInterface {
    requestCustomGrant(requestParams: CustomGrantConfig): Promise<HttpResponse | BasicUserInfo>;
    httpRequest<T = any>(config: HttpRequestConfig): Promise<HttpResponse<T>>;
    httpRequestAll<T = any>(configs: HttpRequestConfig[]): Promise<HttpResponse<T>[]>;
    enableHttpHandler(): Promise<boolean>;
    disableHttpHandler(): Promise<boolean>;
    initialize(): Promise<boolean>;
    signIn(
        params?: SignInConfig,
        authorizationCode?: string,
        sessionState?: string,
        signInRedirectURL?: string
    ): Promise<BasicUserInfo>;
    signOut(signOutRedirectURL?: string): Promise<boolean>;
    revokeAccessToken(): Promise<boolean>;
    getOIDCServiceEndpoints(): Promise<OIDCProviderMetaData>;
    getBasicUserInfo(): Promise<BasicUserInfo>;
    getDecodedIDToken(): Promise<DecodedIdTokenPayload>;
    isAuthenticated(): Promise<boolean>;
    setHttpRequestSuccessCallback(callback: (response: HttpResponse) => void): void;
    setHttpRequestErrorCallback(callback: (response: HttpError) => void): void;
    setHttpRequestStartCallback(callback: () => void): void;
    setHttpRequestFinishCallback(callback: () => void): void;
    refreshAccessToken(): Promise<BasicUserInfo>;
    updateConfig(config: Partial<AuthClientConfig<WebWorkerClientConfig>>): Promise<void>;
}
