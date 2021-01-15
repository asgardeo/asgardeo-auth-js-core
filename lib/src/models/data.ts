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

import { OIDCEndpoints, OIDCProviderMetaData } from ".";
import { AuthClientConfig } from "./client-config";

export type StoreValue = string | string[] | boolean | number | OIDCEndpoints;
export type TemporaryData = { [ key: string ]: StoreValue; };

export interface SessionData {
    access_token: string;
    id_token: string;
    expires_in: string;
    scope: string;
    refresh_token?: string;
    token_type: string;
    session_state: string;
}

export interface DataLayer<T> {
    setSessionData(sessionData: SessionData): Promise<void>;
    setOIDCProviderMetaData(oidcProviderMetaData: OIDCProviderMetaData): Promise<void>;
    setConfigData(config: AuthClientConfig<T>): Promise<void>;
    setTemporaryData(data: TemporaryData): Promise<void>;
    getSessionData(): Promise<SessionData>;
    getOIDCProviderMetaData(): Promise<OIDCProviderMetaData>;
    getConfigData(): Promise<AuthClientConfig<T>>;
    getTemporaryData(): Promise<{ [key: string]: StoreValue }>;
    removeSessionData(): Promise<void>;
    removeOIDCProviderMetaData(): Promise<void>;
    removeConfigData(): Promise<void>;
    removeTemporaryData(): Promise<void>;
    setSessionDataParameter(key: keyof SessionData, value: StoreValue): Promise<void>;
    setOIDCProviderMetaDataParameter(key: keyof OIDCProviderMetaData, value: StoreValue): Promise<void>;
    setConfigDataParameter(key: keyof AuthClientConfig<T>, value: StoreValue): Promise<void>;
    setTemporaryDataParameter(key: string, value: StoreValue): Promise<void>;
    getSessionDataParameter(key: keyof SessionData): Promise<StoreValue>;
    getOIDCProviderMetaDataParameter(key: keyof OIDCProviderMetaData): Promise<StoreValue>;
    getConfigDataParameter(key: keyof AuthClientConfig<T>): Promise<StoreValue>;
    getTemporaryDataParameter(key: string): Promise<StoreValue>;
    removeSessionDataParameter(key: keyof SessionData): Promise<void>;
    removeOIDCProviderMetaDataParameter(key: keyof OIDCProviderMetaData): Promise<void>;
    removeConfigDataParameter(key: keyof AuthClientConfig<T>): Promise<void>;
    removeTemporaryDataParameter(key: string): Promise<void>;
}

export interface Store {
    setData(key: string, value: string): Promise<void>;
    getData(key: string): Promise<string>;
    removeData(key: string): Promise<void>;
}
