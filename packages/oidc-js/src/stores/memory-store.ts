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
import { Store, TemporaryData, StoreValue } from "../core/models/store";
import { ConfigInterface, OIDCProviderMetaData, SessionDataRaw } from "../models";
import { Stores } from "../constants";

export class MemoryStore implements Store {
    private _configData: ConfigInterface;
    private _sessionData: SessionDataRaw;
    private _temporaryData: TemporaryData;
    private _oidcProviderMetaData: OIDCProviderMetaData;

    public setConfigData(config: ConfigInterface): void {
        this._configData = { ...this._configData, ...config };
    }

    public setOIDCProviderMetaData(oidcProviderMetaData: OIDCProviderMetaData): void {
        this._oidcProviderMetaData = { ...this._oidcProviderMetaData, ...oidcProviderMetaData };
    }

    public setTemporaryData(temporaryData: TemporaryData): void {
        this._temporaryData = { ...this._temporaryData, ...temporaryData };
    }

    public setSessionData(sessionData: SessionDataRaw): void {
        this._sessionData = { ...this._sessionData, ...sessionData };
    }

    public getConfigData(): ConfigInterface {
        return this._configData;
    }

    public getOIDCProviderMetaData(): OIDCProviderMetaData {
        return this._oidcProviderMetaData;
    }

    public getTemporaryData(): TemporaryData {
        return this._temporaryData;
    }

    public getSessionData(): SessionDataRaw {
        return this._sessionData;
    }

    public removeConfigData(): void {
        this._configData = null;
    }

    public removeOIDCProviderMetaData(): void {
        this._oidcProviderMetaData = null;
    }

    public removeTemporaryData(): void {
        this._temporaryData = null;
    }

    public removeSessionData(): void {
        this._sessionData = null;
    }

    public getConfigDataParameter(key: keyof ConfigInterface): StoreValue {
        return this._configData[key];
    }

    public getOIDCProviderMetaDataParameter(key: keyof OIDCProviderMetaData): StoreValue {
        return this._oidcProviderMetaData[ key ];
    }

    public getTemporaryDataParameter(key: keyof TemporaryData): StoreValue {
        return this._temporaryData[ key ];
    }

    public getSessionDataParameter(key: keyof SessionDataRaw): StoreValue {
        return this._sessionData[ key ];
    }

    public setConfigDataParameter(key: keyof ConfigInterface, value: StoreValue): void {
        this._configData = { ...this._configData, [key]: value };
    }

    public setOIDCProviderMetaDataParameter(key: keyof OIDCProviderMetaData, value: StoreValue): void {
        this._oidcProviderMetaData = { ...this._oidcProviderMetaData, [key]: value };
    }

    public setTemporaryDataParameter(key: keyof TemporaryData, value: StoreValue): void {
        this._temporaryData = { ...this._temporaryData, [key]: value };
    }

    public setSessionDataParameter(key: keyof SessionDataRaw, value: StoreValue): void {
        this._sessionData = { ...this._sessionData, [key]: value };
    }

    public removeConfigDataParameter(key: keyof ConfigInterface): void {
        delete this._configData[ key ];
    }

    public removeOIDCProviderMetaDataParameter(key: keyof OIDCProviderMetaData): void {
        delete this._oidcProviderMetaData[ key ];
    }

    public removeTemporaryDataParameter(key: keyof TemporaryData): void {
        delete this._temporaryData[ key ];
    }

    public removeSessionDataParameter(key: keyof SessionDataRaw): void {
        delete this._sessionData[ key ];
    }
}
