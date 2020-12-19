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
    API_CALL,
    API_CALL_ALL,
    AUTH_CODE,
    AUTH_REQUIRED,
    CUSTOM_GRANT,
    DISABLE_HTTP_HANDLER,
    ENABLE_HTTP_HANDLER,
    END_USER_SESSION,
    GET_DECODED_ID_TOKEN,
    GET_SERVICE_ENDPOINTS,
    GET_USER_INFO,
    INIT,
    LOGOUT,
    REQUEST_ERROR,
    REQUEST_FINISH,
    REQUEST_START,
    REQUEST_SUCCESS,
    REVOKE_TOKEN,
    SIGNED_IN,
    SIGN_IN,
    GET_AUTH_URL,
    GET_TOKEN,
    IS_AUTHENTICATED,
    GET_SIGN_OUT_URL,
    REFRESH_TOKEN
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
    | typeof LOGOUT
    | typeof API_CALL
    | typeof API_CALL_ALL
    | typeof CUSTOM_GRANT
    | typeof REVOKE_TOKEN
    | typeof END_USER_SESSION
    | typeof REQUEST_ERROR
    | typeof REQUEST_FINISH
    | typeof REQUEST_START
    | typeof REQUEST_SUCCESS
    | typeof GET_SERVICE_ENDPOINTS
    | typeof GET_USER_INFO
    | typeof GET_DECODED_ID_TOKEN
    | typeof ENABLE_HTTP_HANDLER
    | typeof DISABLE_HTTP_HANDLER
    | typeof GET_AUTH_URL
    | typeof GET_TOKEN
    | typeof IS_AUTHENTICATED
    | typeof GET_SIGN_OUT_URL
    | typeof REFRESH_TOKEN;

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
