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
    Config,
    OIDCProviderMetaData,
    SessionDataRaw,
    OIDCEndpointsInternal
} from "../../models";

export interface Store {
    setSessionData(sessionData: SessionDataRaw): void;
    setOIDCProviderMetaData(oidcProviderMetaData: OIDCProviderMetaData | OIDCEndpointsInternal): void;
    setConfigData(config: Config): void;
    setTemporaryData(data: { [key: string]: StoreValue }): void;
    getSessionData(): SessionDataRaw;
    getOIDCProviderMetaData(): OIDCProviderMetaData;
    getConfigData(): Config;
    getTemporaryData(): { [key: string]: StoreValue };
    removeSessionData(): SessionDataRaw;
    removeOIDCProviderMetaData(): OIDCProviderMetaData;
    removeConfigData(): Config;
    removeTemporaryData(): { [key: string]: StoreValue };
    setSessionDataParameter(key: keyof SessionDataRaw, value: StoreValue): void;
    setOIDCProviderMetaDataParameter(key: keyof OIDCProviderMetaData, value: StoreValue): void;
    setConfigDataParameter(key: keyof Config, value: StoreValue): void;
    setTemporaryDataParameter(key: string, value: StoreValue);
    getSessionDataParameter(key: keyof SessionDataRaw): StoreValue;
    getOIDCProviderMetaDataParameter(key: keyof OIDCProviderMetaData): StoreValue;
    getConfigDataParameter(key: keyof Config): StoreValue;
    getTemporaryDataParameter(key: string): StoreValue;
    removeSessionDataParameter(key: keyof SessionDataRaw): StoreValue;
    removeOIDCProviderMetaDataParameter(key: keyof OIDCProviderMetaData): StoreValue;
    removeConfigDataParameter(key: keyof Config): StoreValue;
    removeTemporaryDataParameter(key: string): StoreValue;
}

type StoreValue = string | string[] | boolean | number;
