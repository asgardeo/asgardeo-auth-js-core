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
import { Store, TemporaryData, StoreValue } from "../core/models/data";
import { ConfigInterface, SessionDataRaw } from "../models";
import { Stores } from "../constants";

export class MemoryStore implements Store {
    private _data: Map<string, string>;

    public constructor() {
        this._data = new Map();
    }

    public setData(key: string, value: string): void {
        console.log(key, value);
        this._data.set(key, value);
    }

    public getData(key: string): string {
        return this._data?.get(key);
    }

    public removeData(key: string): void {
        this._data.delete(key);
    }
}