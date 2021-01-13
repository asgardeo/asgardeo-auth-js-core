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

import { AsgardeoAuthClient, DataLayer, REFRESH_TOKEN_TIMER } from "@asgardeo/auth-js";

export class SPAHelper<T> {
    private _authenticationClient: AsgardeoAuthClient<T>;
    private _dataLayer: DataLayer<T>;
    public constructor(authClient: AsgardeoAuthClient<T>) {
        this._authenticationClient = authClient;
        this._dataLayer = this._authenticationClient.getDataLayer();
    }

    public async refreshAccessTokenAutomatically(): Promise<void> {
        const sessionData = await this._dataLayer.getSessionData();
        if (sessionData.refresh_token) {
            // Refresh 10 seconds before the expiry time
            const expiryTime = parseInt(sessionData.expires_in);
            const time = expiryTime <= 10 ? expiryTime : expiryTime - 10;

            const timer = setTimeout(async () => {
                await this._authenticationClient.refreshAccessToken();
            }, time * 1000);

            await this._dataLayer.setTemporaryDataParameter(REFRESH_TOKEN_TIMER, JSON.stringify(timer));
        }
    }

    public async clearRefreshTokenTimeout(): Promise<void> {
        if (await this._dataLayer.getTemporaryDataParameter(REFRESH_TOKEN_TIMER)) {
            const oldTimer = JSON.parse(await this._dataLayer.getTemporaryDataParameter(REFRESH_TOKEN_TIMER) as string);

            clearTimeout(oldTimer);
        }
    }
}
