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

import { Store } from "./models/store";
import { AuthenticationCore } from "./authentication-core";
import { OP_CONFIG_INITIATED, GetAuthorizationURLParameter } from "..";
import { TokenResponseInterface, DecodedIdTokenPayloadInterface, OIDCEndpointConstantsInterface, UserInfo, CustomGrantRequestParams } from "../models";
import { AxiosResponse } from "axios";
import { Config } from "./models/config";
import { DataLayer } from "./data-layer";

export class AuthenticationClient {
    private _dataLayer: DataLayer;
    private _authenticationCore: AuthenticationCore;

    private static _instanceID: number;

    public constructor(config: Config, store: Store) {
        if (!AuthenticationClient._instanceID) {
            AuthenticationClient._instanceID = 0;
        } else {
            AuthenticationClient._instanceID = AuthenticationClient._instanceID++;
        }
        this._dataLayer = new DataLayer(`Instance_${AuthenticationClient._instanceID}`, store);
        this._authenticationCore = new AuthenticationCore(this._dataLayer);
        this._dataLayer.setConfigData(config);
    }

    public getDataLayer(): DataLayer{
        return this._dataLayer;
    }

    public getAuthorizationURL(config?: GetAuthorizationURLParameter): Promise<string> {
        const authRequestConfig = { ...config };
        delete authRequestConfig?.forceInit;
        if (this._dataLayer.getTemporaryDataParameter(OP_CONFIG_INITIATED)) {
            return Promise.resolve(this._authenticationCore.sendAuthorizationRequest(authRequestConfig));
        }

        return this._authenticationCore.initOPConfiguration(config?.forceInit).then(() => {
            return this._authenticationCore.sendAuthorizationRequest(authRequestConfig);
        });
    }

    public sendTokenRequest(authorizationCode: string, sessionState: string): Promise<TokenResponseInterface> {
        if (this._dataLayer.getTemporaryDataParameter(OP_CONFIG_INITIATED)) {
            return this._authenticationCore.sendTokenRequest(authorizationCode, sessionState);
        }

        return this._authenticationCore.initOPConfiguration(false).then(() => {
            return this._authenticationCore.sendTokenRequest(authorizationCode, sessionState);
        });
    }

    public getSignOutURL(): string {
        return this._authenticationCore.getSignOutURL();
    }

    public getOIDCEndpoints(): OIDCEndpointConstantsInterface{
        return this._authenticationCore.getServiceEndpoints();
    }

    public getDecodedIDToken(): DecodedIdTokenPayloadInterface{
        return this._authenticationCore.getDecodedIDToken();
    }

    public getUserInfo(): UserInfo {
        return this._authenticationCore.getUserInfo();
    }

    public revokeToken(): Promise<AxiosResponse>{
        return this._authenticationCore.sendRevokeTokenRequest();
    }

    public refreshToken(): Promise<TokenResponseInterface>{
        return this._authenticationCore.sendRefreshTokenRequest();
    }

    public getAccessToken(): string {
        return this._authenticationCore.getAccessToken();
    }

    public sendCustomGrantRequest(config: CustomGrantRequestParams): Promise<TokenResponseInterface | AxiosResponse>{
        return this._authenticationCore.customGrant(config);
    }

    public isAuthenticated():boolean {
        return this._authenticationCore.isAuthenticated();
    }

}
