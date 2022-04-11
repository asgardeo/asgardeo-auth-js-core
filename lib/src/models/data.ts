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

import { OIDCEndpoints } from ".";

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
    created_at: number;
}

export interface Store {
    setData(key: string, value: string): Promise<void>;
    getData(key: string): Promise<string>;
    removeData(key: string): Promise<void>;
}
