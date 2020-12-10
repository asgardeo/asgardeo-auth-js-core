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

import { OIDCEndpoints } from "./endpoints";
import { SessionData } from "./web-worker-client";
import { ResponseMode, Storage } from "../constants";
import { HttpError, HttpResponse } from "../models";

interface BaseConfigInterface {
    authorizationType?: string;
    signInRedirectURL: string;
    signOutRedirectURL?: string;
    clientHost?: string;
    clientID: string;
    clientSecret?: string;
    consentDenied?: boolean;
    enablePKCE?: boolean;
    prompt?: string;
    responseMode?: ResponseMode;
    scope?: string[];
    serverOrigin: string;
    endpoints?: OIDCEndpoints;
    overrideWellEndpointConfig?: boolean;
    wellKnownEndpoint?: string;
    authorizationCode?: string;
    sessionState?: string;
    validateIDToken?: boolean;
    /**
     * Allowed leeway for id_tokens (in seconds).
     */
    clockTolerance?: number;
}

/**
 * SDK Client config parameters.
 */
export interface NonWebWorkerConfigInterface extends BaseConfigInterface{
    storage?: Storage.SessionStorage | Storage.LocalStorage;
}

export interface WebWorkerConfigInterface extends BaseConfigInterface {
    resourceServerURLs: string[];
    session?: SessionData;
    storage: Storage.WebWorker;
    requestTimeout?: number;
}

export type ConfigInterface = NonWebWorkerConfigInterface | WebWorkerConfigInterface;

export interface HttpClient {
    requestStartCallback: () => void;
    requestSuccessCallback: (response: HttpResponse) => void;
    requestErrorCallback: (error: HttpError) => void;
    requestFinishCallback: () => void;
}

export interface WebWorkerClientConfigInterface extends WebWorkerConfigInterface {
    httpClient: HttpClient;
}

export type SendAuthorizationRequestParameter = Omit<GetAuthorizationURLParameter, "forceInit">

export interface GetAuthorizationURLParameter {
    fidp?: string;
    forceInit?: boolean;
    [ key: string ]: string | boolean;
}
