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

import { WebWorkerClientConfigInterface } from "./client";
import { ServiceResourcesType } from "./endpoints";
import { Message, SignInResponse, UserInfo } from "./message";
import { DecodedIdTokenPayloadInterface } from "./token-response";
import { CustomGrantRequestParams } from "./web-worker-client";
import { HttpRequestConfig, HttpResponse } from "../models";

export interface WebWorkerInterface {
    isSignedIn(): boolean;
    doesTokenExist(): boolean;
    setAuthCode(authCode: string, sessionState: string, pkce?: string): void;
    signIn(fidp?: string): Promise<SignInResponse>;
    refreshAccessToken(): Promise<boolean>;
    signOut(): Promise<string>;
    httpRequest(config: HttpRequestConfig): Promise<HttpResponse>;
    httpRequestAll(configs: HttpRequestConfig[]): Promise<HttpResponse[]>;
    customGrant(requestParams: CustomGrantRequestParams): Promise<HttpResponse | boolean | SignInResponse>;
    getUserInfo(): UserInfo;
    endUserSession(): Promise<boolean>;
    getServiceEndpoints(): Promise<ServiceResourcesType>;
    getDecodedIDToken(): DecodedIdTokenPayloadInterface;
}

export interface WebWorkerSingletonInterface {
    getInstance(config: WebWorkerClientConfigInterface): WebWorkerInterface;
}

interface WebWorkerEvent<T> extends MessageEvent {
    data: Message<T>;
}

export class WebWorkerClass<T> extends Worker {
    public onmessage: (this: WebWorkerClass<T>, event: WebWorkerEvent<T>) => void;
}
