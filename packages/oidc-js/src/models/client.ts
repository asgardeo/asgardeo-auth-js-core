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
import { HttpError, HttpResponse, HttpRequestConfig } from "../models";
import { HttpClientInstance } from "../http-client";
import { SignInConfig, BasicUserInfo, CustomGrantConfig, DecodedIdTokenPayload, OIDCEndpoints, OIDCProviderMetaData, TokenResponse } from "../core";

/**
 * SDK Client config parameters.
 */
export interface MainThreadClientConfig {
    storage?: Storage.SessionStorage | Storage.LocalStorage | Storage.MainThreadMemory;
}

export interface WebWorkerClientConfig {
    resourceServerURLs: string[];
    storage: Storage.WebWorker;
    requestTimeout?: number;
}

export type Config=MainThreadClientConfig | WebWorkerClientConfig;

export interface HttpClient {
    requestStartCallback: () => void;
    requestSuccessCallback: (response: HttpResponse) => void;
    requestErrorCallback: (error: HttpError) => void;
    requestFinishCallback: () => void;
}

export interface MainThreadClientInterface {
    setHttpRequestStartCallback(callback: () => void): void;
    setHttpRequestSuccessCallback(callback: (response: HttpResponse) => void): void;
    setHttpRequestFinish(callback: () => void): void;
    setHttpRequestError(callback: (error: HttpError) => void): void
    httpRequest(config: HttpRequestConfig): Promise<HttpResponse>;
    httpRequestAll(config: HttpRequestConfig[]): Promise<HttpResponse[]>;
    getHttpClient(): HttpClientInstance;
    enableHttpHandler(): void;
    disableHttpHandler(): void;
    signIn(
        config?: SignInConfig,
        authorizationCode?: string,
        sessionState?: string
    ): Promise<BasicUserInfo> ;
    signOut(): void;
    customGrant(config: CustomGrantConfig): Promise<BasicUserInfo | HttpResponse>;
    refreshToken(): Promise<BasicUserInfo>;
    revokeAccessToken(): Promise<boolean>;
    getUserInfo(): BasicUserInfo;
    getDecodedIDToken(): DecodedIdTokenPayload;
    getOIDCServiceEndpoints(): OIDCEndpoints;
    getAccessToken(): string;
    isAuthenticated(): boolean;
}

export interface WebWorkerClientInterface {
     customGrant(
        requestParams: CustomGrantConfig
    ): Promise<HttpResponse |TokenResponse>;
    httpRequest<T = any>(config: HttpRequestConfig): Promise<HttpResponse<T>>;
    httpRequestAll<T = any>(configs: HttpRequestConfig[]): Promise<HttpResponse<T>[]>;
    enableHttpHandler(): Promise<boolean>;
    disableHttpHandler(): Promise<boolean>;
    initialize(): Promise<boolean>;
    signIn(
        params?: SignInConfig,
        authorizationCode?: string,
        sessionState?: string
    ): Promise<BasicUserInfo>;
    signOut(): Promise<boolean> ;
    endUserSession(): Promise<boolean>;
    getServiceEndpoints(): Promise<OIDCProviderMetaData>;
    getUserInfo(): Promise<BasicUserInfo>;
    getDecodedIDToken(): Promise<DecodedIdTokenPayload>;
    isAuthenticated(): Promise<boolean>;
    onHttpRequestSuccess(callback: (response: HttpResponse) => void): void;
    onHttpRequestError(callback: (response: HttpError) => void): void;
    onHttpRequestStart(callback: () => void): void;
    onHttpRequestFinish(callback: () => void): void;
}
