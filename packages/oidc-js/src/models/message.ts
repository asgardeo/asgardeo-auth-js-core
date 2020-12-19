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
    HTTP_REQUEST,
    HTTP_REQUEST_ALL,
    AUTH_CODE,
    AUTH_REQUIRED,
    REQUEST_CUSTOM_GRANT,
    DISABLE_HTTP_HANDLER,
    ENABLE_HTTP_HANDLER,
    END_USER_SESSION,
    GET_DECODED_ID_TOKEN,
    GET_OIDC_SERVICE_ENDPOINTS,
    GET_BASIC_USER_INFO,
    INIT,
    SIGN_OUT,
    REQUEST_ERROR,
    REQUEST_FINISH,
    REQUEST_START,
    REQUEST_SUCCESS,
    REVOKE_ACCESS_TOKEN,
    SIGNED_IN,
    SIGN_IN,
    GET_AUTH_URL,
    REQUEST_ACCESS_TOKEN,
    IS_AUTHENTICATED,
    GET_SIGN_OUT_URL,
    REFRESH_ACCESS_TOKEN
} from "../constants";
import { SignInConfig } from "../core";

export interface ResponseMessage<T> {
    success: boolean;
    error?: string;
    data?: T;
    blob?: Blob;
}

export interface Message<T> {
    type: MessageType;
    data?: T;
}


export interface AuthCode {
    code: string;
    sessionState: string;
    pkce?: string;
    signInRedirectURL?: string;
}

export type MessageType =
    | typeof INIT
    | typeof SIGN_IN
    | typeof AUTH_CODE
    | typeof SIGN_OUT
    | typeof HTTP_REQUEST
    | typeof HTTP_REQUEST_ALL
    | typeof REQUEST_CUSTOM_GRANT
    | typeof REVOKE_ACCESS_TOKEN
    | typeof END_USER_SESSION
    | typeof REQUEST_ERROR
    | typeof REQUEST_FINISH
    | typeof REQUEST_START
    | typeof REQUEST_SUCCESS
    | typeof GET_OIDC_SERVICE_ENDPOINTS
    | typeof GET_BASIC_USER_INFO
    | typeof GET_DECODED_ID_TOKEN
    | typeof ENABLE_HTTP_HANDLER
    | typeof DISABLE_HTTP_HANDLER
    | typeof GET_AUTH_URL
    | typeof REQUEST_ACCESS_TOKEN
    | typeof IS_AUTHENTICATED
    | typeof GET_SIGN_OUT_URL
    | typeof REFRESH_ACCESS_TOKEN;

export interface CommunicationHelperInterface {
    communicate: <T, R>(message: Message<T>) => Promise<R>;
}

export interface GetAuthorizationURLInterface{
    authorizationCode: string;
    pkce?: string;
}

export interface AuthUrl {
    params: SignInConfig,
    signInRedirectURL?: string
}
