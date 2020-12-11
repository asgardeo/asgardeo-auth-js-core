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

export class SessionStore implements Store {
    private setDataInBulk(
        key: Stores,
        data: ConfigInterface | OIDCProviderMetaData | SessionDataRaw | TemporaryData
    ): void {
        const existingDataJSON = sessionStorage.getItem(key);
        const existingData = existingDataJSON && JSON.parse(existingDataJSON);

        const dataToBeSaved = { ...existingData, ...data };
        const dataToBeSavedJSON = JSON.stringify(dataToBeSaved);
        sessionStorage.setItem(key, dataToBeSavedJSON);
    }

    private setValue(
        key: Stores,
        attribute: keyof ConfigInterface | keyof OIDCProviderMetaData | keyof SessionDataRaw | keyof TemporaryData,
        value: StoreValue
    ): void {
        const existingDataJSON = sessionStorage.getItem(key);
        const existingData = existingDataJSON && JSON.parse(existingDataJSON);

        const dataToBeSaved = { ...existingData, [attribute]: value };
        const dataToBeSavedJSON = JSON.stringify(dataToBeSaved);

        sessionStorage.setItem(key, dataToBeSavedJSON);
    }

    private removeValue(
        key: Stores,
        attribute: keyof ConfigInterface | keyof OIDCProviderMetaData | keyof SessionDataRaw | keyof TemporaryData
    ): void {
        const existingDataJSON = sessionStorage.getItem(key);
        const existingData = existingDataJSON && JSON.parse(existingDataJSON);

        const dataToBeSaved = { ...existingData };
        delete dataToBeSaved[attribute];
        const dataToBeSavedJSON = JSON.stringify(dataToBeSaved);

        sessionStorage.setItem(key, dataToBeSavedJSON);
    }

    private;
    public setConfigData(config: ConfigInterface): void {
        this.setDataInBulk(Stores.ConfigData, config);
    }

    public setOIDCProviderMetaData(oidcProviderMetaData: OIDCProviderMetaData): void {
        this.setDataInBulk(Stores.OIDCProviderMetaData, oidcProviderMetaData);
    }

    public setTemporaryData(temporaryData: TemporaryData): void {
        this.setDataInBulk(Stores.TemporaryData, temporaryData);
    }

    public setSessionData(sessionData: SessionDataRaw): void {
        this.setDataInBulk(Stores.SessionData, sessionData);
    }

    public getConfigData(): ConfigInterface {
        return JSON.parse(sessionStorage.getItem(Stores.ConfigData));
    }

    public getOIDCProviderMetaData(): OIDCProviderMetaData {
        return JSON.parse(sessionStorage.getItem(Stores.OIDCProviderMetaData));
    }

    public getTemporaryData(): TemporaryData {
        return JSON.parse(sessionStorage.getItem(Stores.TemporaryData));
    }

    public getSessionData(): SessionDataRaw {
        return JSON.parse(sessionStorage.getItem(Stores.SessionData));
    }

    public removeConfigData(): void {
        sessionStorage.removeItem(Stores.ConfigData);
    }

    public removeOIDCProviderMetaData(): void {
        sessionStorage.removeItem(Stores.OIDCProviderMetaData);
    }

    public removeTemporaryData(): void {
        sessionStorage.removeItem(Stores.TemporaryData);
    }

    public removeSessionData(): void {
        sessionStorage.removeItem(Stores.SessionData);
    }

    public getConfigDataParameter(key: keyof ConfigInterface): StoreValue {
        return sessionStorage.getItem(Stores.ConfigData) && JSON.parse(sessionStorage.getItem(Stores.ConfigData))[key];
    }

    public getOIDCProviderMetaDataParameter(key: keyof OIDCProviderMetaData): StoreValue {
        return (
            sessionStorage.getItem(Stores.OIDCProviderMetaData) &&
            JSON.parse(sessionStorage.getItem(Stores.OIDCProviderMetaData))[key]
        );
    }

    public getTemporaryDataParameter(key: keyof TemporaryData): StoreValue {
        return (
            sessionStorage.getItem(Stores.TemporaryData) &&
            JSON.parse(sessionStorage.getItem(Stores.TemporaryData))[key]
        );
    }

    public getSessionDataParameter(key: keyof SessionDataRaw): StoreValue {
        return (
            sessionStorage.getItem(Stores.SessionData) && JSON.parse(sessionStorage.getItem(Stores.SessionData))[key]
        );
    }

    public setConfigDataParameter(key: keyof ConfigInterface, value: StoreValue): void {
        this.setValue(Stores.ConfigData, key, value);
    }

    public setOIDCProviderMetaDataParameter(key: keyof OIDCProviderMetaData, value: StoreValue): void {
        this.setValue(Stores.OIDCProviderMetaData, key, value);
    }

    public setTemporaryDataParameter(key: keyof TemporaryData, value: StoreValue): void {
        this.setValue(Stores.TemporaryData, key, value);
    }

    public setSessionDataParameter(key: keyof SessionDataRaw, value: StoreValue): void {
        this.setValue(Stores.SessionData, key, value);
    }

    public removeConfigDataParameter(key: keyof ConfigInterface): void {
        this.removeValue(Stores.ConfigData, key);
    }

    public removeOIDCProviderMetaDataParameter(key: keyof OIDCProviderMetaData): void {
        this.removeValue(Stores.OIDCProviderMetaData, key);
    }

    public removeTemporaryDataParameter(key: keyof TemporaryData): void {
        this.removeValue(Stores.TemporaryData, key);
    }

    public removeSessionDataParameter(key: keyof SessionDataRaw): void {
        this.removeValue(Stores.SessionData, key);
    }
}
