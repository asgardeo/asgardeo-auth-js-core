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

import { AuthenticationCore } from "./core";
import { AuthClientConfig, OIDCEndpoints, CustomGrantConfig, TokenResponse, DecodedIdTokenPayload, Store, AuthorizationURLParams, BasicUserInfo } from "./models";
import { OP_CONFIG_INITIATED, SIGN_OUT_SUCCESS_PARAM } from "./constants";
import { DataLayer } from "./data";
import { HttpResponse } from "../models";

export class AsgardeoAuthClient<T> {
    private _dataLayer: DataLayer<T>;
    private _authenticationCore: AuthenticationCore<T>;

    private static _instanceID: number;

    public constructor(config: AuthClientConfig<T>, store: Store) {
        if (!AsgardeoAuthClient._instanceID) {
            AsgardeoAuthClient._instanceID = 0;
        } else {
            AsgardeoAuthClient._instanceID += 1;
        }
        this._dataLayer = new DataLayer<T>(`instance_${AsgardeoAuthClient._instanceID}`, store);
        this._authenticationCore = new AuthenticationCore(this._dataLayer);
        this._dataLayer.setConfigData(config);
    }

    public getDataLayer(): DataLayer<T>{
        return this._dataLayer;
    }

    public getAuthorizationURL(config?: AuthorizationURLParams): Promise<string> {
        const authRequestConfig = { ...config };
        delete authRequestConfig?.forceInit;
        if (this._dataLayer.getTemporaryDataParameter(OP_CONFIG_INITIATED)) {
            return Promise.resolve(this._authenticationCore.sendAuthorizationRequest(authRequestConfig));
        }

        return this._authenticationCore.initOPConfiguration(config?.forceInit as boolean).then(() => {
            return this._authenticationCore.sendAuthorizationRequest(authRequestConfig);
        });
    }

    public sendTokenRequest(authorizationCode: string, sessionState: string): Promise<TokenResponse> {
        if (this._dataLayer.getTemporaryDataParameter(OP_CONFIG_INITIATED)) {
            return this._authenticationCore.sendTokenRequest(authorizationCode, sessionState);
        }

        return this._authenticationCore.initOPConfiguration(false).then(() => {
            return this._authenticationCore.sendTokenRequest(authorizationCode, sessionState);
        });
    }

    public signOut(): string {
        console.log("sign out client methd");
        return this._authenticationCore.signOut();
    }

    public getSignOutURL(): string{
        return this._authenticationCore.getSignOutURL();
    }

    public getOIDCEndpoints(): OIDCEndpoints{
        return this._authenticationCore.getServiceEndpoints();
    }

    public getDecodedIDToken(): DecodedIdTokenPayload{
        return this._authenticationCore.getDecodedIDToken();
    }

    public getBasicUserInfo(): BasicUserInfo {
        return this._authenticationCore.getBasicUserInfo();
    }

    public revokeToken(): Promise<HttpResponse>{
        return this._authenticationCore.sendRevokeTokenRequest();
    }

    public refreshToken(): Promise<TokenResponse>{
        return this._authenticationCore.sendRefreshTokenRequest();
    }

    public getAccessToken(): string {
        return this._authenticationCore.getAccessToken();
    }

    public sendCustomGrantRequest(config: CustomGrantConfig): Promise<TokenResponse | HttpResponse>{
        return this._authenticationCore.customGrant(config);
    }

    public isAuthenticated():boolean {
        return this._authenticationCore.isAuthenticated();
    }

    public getPKCECode(): string{
        return this._authenticationCore.getPKCECode();
    }

    public setPKCECode(pkce: string): void {
        this._authenticationCore.setPKCECode(pkce);
    }

    public static isSignOutSuccessful(signOutUrl: string): boolean{
        const url = new URL(signOutUrl);
        const stateParam = url.searchParams.get("state");
        const error = Boolean(url.searchParams.get("error"));

        return stateParam && stateParam === SIGN_OUT_SUCCESS_PARAM && !error;
    }
}
