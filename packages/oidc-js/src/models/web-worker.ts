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

import { Message, HttpResponse, HttpError, HttpRequestConfig, GetAuthorizationURLInterface } from ".";
import { BasicUserInfo, CustomGrantConfig, AuthorizationURLParams, DecodedIdTokenPayload, OIDCEndpoints } from "../core";

interface WebWorkerEvent<T> extends MessageEvent {
    data: Message<T>;
}

export class WebWorkerClass<T> extends Worker {
    public onmessage: (this: WebWorkerClass<T>, event: WebWorkerEvent<T>) => void;
}

export interface WebWorkerCoreInterface {
    setHttpRequestStartCallback(callback: () => void): void;
    setHttpRequestSuccessCallback(callback: (response: HttpResponse) => void): void;
    setHttpRequestFinish(callback: () => void): void;
    setHttpRequestError(callback: (error: HttpError) => void): void;
    httpRequest(config: HttpRequestConfig): Promise<HttpResponse>;
    httpRequestAll(configs: HttpRequestConfig[]): Promise<HttpResponse[]>;
    enableHttpHandler(): void;
    disableHttpHandler(): void;
    getAuthorizationURL(params?: AuthorizationURLParams): Promise<GetAuthorizationURLInterface>;
    sendTokenRequest(authorizationCode?: string, sessionState?: string, pkce?: string): Promise<BasicUserInfo>;
    signOut(): string;
    getSignOutURL(): string;
    customGrant(config: CustomGrantConfig): Promise<BasicUserInfo | HttpResponse>;
    refreshToken(): Promise<BasicUserInfo>;
    revokeToken(): Promise<boolean>;
    getUserInfo(): BasicUserInfo;
    getDecodedIDToken(): DecodedIdTokenPayload ;
    getOIDCServiceEndpoints(): OIDCEndpoints;
    getAccessToken(): string;
    isAuthenticated(): boolean;
}
