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

import { Stores } from "../constants";
import { AuthClientConfig, OIDCProviderMetaData, SessionData, Store, StoreValue, TemporaryData } from "../models";

export class DataLayer<T> {
    protected _id: string;
    protected _store: Store;
    public constructor(instanceID: string, store: Store) {
        this._id = instanceID;
        this._store = store;
    }

    protected async setDataInBulk(
        key: string,
        data: Partial<AuthClientConfig<T> | OIDCProviderMetaData | SessionData | TemporaryData>
    ): Promise<void> {
        const existingDataJSON = (await this._store.getData(key)) ?? null;
        const existingData = existingDataJSON && JSON.parse(existingDataJSON);

        const dataToBeSaved = { ...existingData, ...data };
        const dataToBeSavedJSON = JSON.stringify(dataToBeSaved);
        await this._store.setData(key, dataToBeSavedJSON);
    }

    protected async setValue(
        key: string,
        attribute: keyof AuthClientConfig<T> | keyof OIDCProviderMetaData | keyof SessionData | keyof TemporaryData,
        value: StoreValue
    ): Promise<void> {
        const existingDataJSON = (await this._store.getData(key)) ?? null;
        const existingData = existingDataJSON && JSON.parse(existingDataJSON);

        const dataToBeSaved = { ...existingData, [ attribute ]: value };
        const dataToBeSavedJSON = JSON.stringify(dataToBeSaved);

        await this._store.setData(key, dataToBeSavedJSON);
    }

    protected async removeValue(
        key: string,
        attribute: keyof AuthClientConfig<T> | keyof OIDCProviderMetaData | keyof SessionData | keyof TemporaryData
    ): Promise<void> {
        const existingDataJSON = (await this._store.getData(key)) ?? null;
        const existingData = existingDataJSON && JSON.parse(existingDataJSON);

        const dataToBeSaved = { ...existingData };
        delete dataToBeSaved[ attribute ];
        const dataToBeSavedJSON = JSON.stringify(dataToBeSaved);
        await this._store.setData(key, dataToBeSavedJSON);
    }

    protected _resolveKey(store: Stores | string, userID?: string): string {
        return userID ? `${ store }-${ this._id }-${ userID }` : `${ store }-${ this._id }`;
    }

    public async setConfigData(config: Partial<AuthClientConfig<T>>): Promise<void> {
        await this.setDataInBulk(this._resolveKey(Stores.ConfigData), config);
    }

    public async setOIDCProviderMetaData(oidcProviderMetaData: Partial<OIDCProviderMetaData>): Promise<void> {
        this.setDataInBulk(this._resolveKey(Stores.OIDCProviderMetaData), oidcProviderMetaData);
    }

    public async setTemporaryData(temporaryData: Partial<TemporaryData>, userID?: string): Promise<void> {
        this.setDataInBulk(this._resolveKey(Stores.TemporaryData, userID), temporaryData);
    }

    public async setSessionData(sessionData: Partial<SessionData>, userID?: string): Promise<void> {
        this.setDataInBulk(this._resolveKey(Stores.SessionData, userID), sessionData);
    }

    public async setCustomData<K>(key: string, customData: Partial<K>, userID?: string): Promise<void> {
        this.setDataInBulk(this._resolveKey(key, userID), customData);
    }

    public async getConfigData(): Promise<AuthClientConfig<T>> {
        return JSON.parse((await this._store.getData(this._resolveKey(Stores.ConfigData))) ?? null);
    }

    public async getOIDCProviderMetaData(): Promise<OIDCProviderMetaData> {
        return JSON.parse((await this._store.getData(this._resolveKey(Stores.OIDCProviderMetaData))) ?? null);
    }

    public async getTemporaryData(userID?: string): Promise<TemporaryData> {
        return JSON.parse((await this._store.getData(this._resolveKey(Stores.TemporaryData, userID))) ?? null);
    }

    public async getSessionData(userID?: string): Promise<SessionData> {
        return JSON.parse((await this._store.getData(this._resolveKey(Stores.SessionData, userID))) ?? null);
    }

    public async getCustomData<K>(key: string, userID?: string): Promise<K> {
        return JSON.parse((await this._store.getData(this._resolveKey(key, userID))) ?? null);
    }

    public async removeConfigData(): Promise<void> {
        await this._store.removeData(this._resolveKey(Stores.ConfigData));
    }

    public async removeOIDCProviderMetaData(): Promise<void> {
        await this._store.removeData(this._resolveKey(Stores.OIDCProviderMetaData));
    }

    public async removeTemporaryData(userID?: string): Promise<void> {
        await this._store.removeData(this._resolveKey(Stores.TemporaryData, userID));
    }

    public async removeSessionData(userID?: string): Promise<void> {
        await this._store.removeData(this._resolveKey(Stores.SessionData, userID));
    }

    public async getConfigDataParameter(key: keyof AuthClientConfig<T>): Promise<StoreValue> {
        const data = await this._store.getData(this._resolveKey(Stores.ConfigData));

        return data && JSON.parse(data)[ key ];
    }

    public async getOIDCProviderMetaDataParameter(key: keyof OIDCProviderMetaData): Promise<StoreValue> {
        const data = await this._store.getData(this._resolveKey(Stores.OIDCProviderMetaData));

        return data && JSON.parse(data)[ key ];
    }

    public async getTemporaryDataParameter(key: keyof TemporaryData, userID?: string): Promise<StoreValue> {
        const data = await this._store.getData(this._resolveKey(Stores.TemporaryData, userID));

        return data && JSON.parse(data)[ key ];
    }

    public async getSessionDataParameter(key: keyof SessionData, userID?: string): Promise<StoreValue> {
        const data = await this._store.getData(this._resolveKey(Stores.SessionData, userID));

        return data && JSON.parse(data)[ key ];
    }

    public async setConfigDataParameter(key: keyof AuthClientConfig<T>, value: StoreValue): Promise<void> {
        await this.setValue(this._resolveKey(Stores.ConfigData), key, value);
    }

    public async setOIDCProviderMetaDataParameter(key: keyof OIDCProviderMetaData, value: StoreValue): Promise<void> {
        await this.setValue(this._resolveKey(Stores.OIDCProviderMetaData), key, value);
    }

    public async setTemporaryDataParameter(
        key: keyof TemporaryData,
        value: StoreValue,
        userID?: string
    ): Promise<void> {
        await this.setValue(this._resolveKey(Stores.TemporaryData, userID), key, value);
    }

    public async setSessionDataParameter(key: keyof SessionData, value: StoreValue, userID?: string): Promise<void> {
        await this.setValue(this._resolveKey(Stores.SessionData, userID), key, value);
    }

    public async removeConfigDataParameter(key: keyof AuthClientConfig<T>): Promise<void> {
        await this.removeValue(this._resolveKey(Stores.ConfigData), key);
    }

    public async removeOIDCProviderMetaDataParameter(key: keyof OIDCProviderMetaData): Promise<void> {
        await this.removeValue(this._resolveKey(Stores.OIDCProviderMetaData), key);
    }

    public async removeTemporaryDataParameter(key: keyof TemporaryData, userID?: string): Promise<void> {
        await this.removeValue(this._resolveKey(Stores.TemporaryData, userID), key);
    }

    public async removeSessionDataParameter(key: keyof SessionData, userID?: string): Promise<void> {
        await this.removeValue(this._resolveKey(Stores.SessionData, userID), key);
    }
}
