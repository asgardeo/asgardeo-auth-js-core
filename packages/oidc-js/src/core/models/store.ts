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
    OIDCProviderMetaData,
    SessionDataRaw,
    OIDCEndpointsInternal,
    OIDCEndpoints
} from "../../models";
import { Config } from "./config";

export interface DataLayer {
    setSessionData(sessionData: SessionDataRaw): void;
    setOIDCProviderMetaData(oidcProviderMetaData: OIDCProviderMetaData | OIDCEndpointsInternal): void;
    setConfigData(config: Config): void;
    setTemporaryData(data: TemporaryData): void;
    getSessionData(): SessionDataRaw;
    getOIDCProviderMetaData(): OIDCProviderMetaData;
    getConfigData(): Config;
    getTemporaryData(): { [key: string]: StoreValue };
    removeSessionData(): void;
    removeOIDCProviderMetaData(): void;
    removeConfigData(): void;
    removeTemporaryData(): void;
    setSessionDataParameter(key: keyof SessionDataRaw, value: StoreValue): void;
    setOIDCProviderMetaDataParameter(key: keyof OIDCProviderMetaData, value: StoreValue): void;
    setConfigDataParameter(key: keyof Config, value: StoreValue): void;
    setTemporaryDataParameter(key: string, value: StoreValue);
    getSessionDataParameter(key: keyof SessionDataRaw): StoreValue;
    getOIDCProviderMetaDataParameter(key: keyof OIDCProviderMetaData): StoreValue;
    getConfigDataParameter(key: keyof Config): StoreValue;
    getTemporaryDataParameter(key: string): StoreValue;
    removeSessionDataParameter(key: keyof SessionDataRaw): void;
    removeOIDCProviderMetaDataParameter(key: keyof OIDCProviderMetaData): void;
    removeConfigDataParameter(key: keyof Config): void;
    removeTemporaryDataParameter(key: string): void;
}

export interface Store {
    setData(key: string, value: string);
    getData(key: string);
    removeData(key: string);
}

export type StoreValue = string | string[] | boolean | number | OIDCEndpoints;
export type TemporaryData = { [ key: string ]: StoreValue; };
