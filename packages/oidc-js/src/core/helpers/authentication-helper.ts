import axios from "axios";
import { KeyLike } from "crypto";
import { DataLayer } from "../data";
import { OIDCProviderMetaData, OIDCEndpointsInternal, AuthClientConfig } from "../models";
import { AuthenticationUtils } from "../utils";
import { SERVICE_RESOURCES, AUTHORIZATION_ENDPOINT, END_SESSION_ENDPOINT, JWKS_ENDPOINT, OIDC_SESSION_IFRAME_ENDPOINT, REVOKE_TOKEN_ENDPOINT, TOKEN_ENDPOINT, TOKEN_TAG, USERNAME_TAG, SCOPE_TAG, CLIENT_ID_TAG, CLIENT_SECRET_TAG, OIDC_SCOPE } from "../constants";
import { CryptoHelper } from ".";

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
export class AuthenticationHelper {
    private _dataLayer: DataLayer;
    private _config: ()=>AuthClientConfig;
    private _oidcProviderMetaData: ()=>OIDCProviderMetaData;

    public constructor(dataLayer: DataLayer) {
        this._dataLayer = dataLayer;
        this._config = ()=>this._dataLayer.getConfigData();
        this._oidcProviderMetaData = ()=>this._dataLayer.getOIDCProviderMetaData();
    }

    public resolveWellKnownEndpoint(): string {
        if (this._config().wellKnownEndpoint) {
            return this._config().serverOrigin + this._config().wellKnownEndpoint;
        }

        return this._config().serverOrigin + SERVICE_RESOURCES.wellKnownEndpoint;
    }

    public resolveEndpoints(response: OIDCProviderMetaData): OIDCProviderMetaData {
        const oidcProviderMetaData = {};
        this._config().endpoints &&
            Object.keys(this._config().endpoints).forEach((endpointName: string) => {
                const camelCasedName = endpointName
                    .split("_")
                    .map((name: string, index: number) => {
                        if (index !== 0) {
                            return name[0].toUpperCase() + name.substring(1);
                        }

                        return name;
                    })
                    .join("");

                if (this._config().overrideWellEndpointConfig && this._config().endpoints[camelCasedName]) {
                    oidcProviderMetaData[camelCasedName] = this._config().endpoints[camelCasedName];
                }
            });

        return { ...response, ...oidcProviderMetaData };
    }

    public resolveFallbackEndpoints(): OIDCEndpointsInternal {
        const oidcProviderMetaData = {};
        this._config().endpoints &&
            Object.keys(this._config().endpoints).forEach((endpointName: string) => {
                const camelCasedName = endpointName
                    .split("_")
                    .map((name: string, index: number) => {
                        if (index !== 0) {
                            return name[0].toUpperCase() + name.substring(1);
                        }

                        return name;
                    })
                    .join("");

                oidcProviderMetaData[ camelCasedName ] = this._config().endpoints[ camelCasedName ];
            });

        const defaultEndpoints = {
            [AUTHORIZATION_ENDPOINT]: this._config().serverOrigin + SERVICE_RESOURCES.authorizationEndpoint,
            [END_SESSION_ENDPOINT]: this._config().serverOrigin + SERVICE_RESOURCES.endSessionEndpoint,
            [JWKS_ENDPOINT]: this._config().serverOrigin + SERVICE_RESOURCES.jwksUri,
            [OIDC_SESSION_IFRAME_ENDPOINT]: this._config().serverOrigin + SERVICE_RESOURCES.checkSessionIframe,
            [REVOKE_TOKEN_ENDPOINT]: this._config().serverOrigin + SERVICE_RESOURCES.revocationEndpoint,
            [TOKEN_ENDPOINT]: this._config().serverOrigin + SERVICE_RESOURCES.tokenEndpoint
        };

        return { ...defaultEndpoints, ...oidcProviderMetaData };
    }

    public validateIdToken(idToken: string): Promise<any> {
        const jwksEndpoint = this._dataLayer.getOIDCProviderMetaData().jwks_uri;

        if (!jwksEndpoint || jwksEndpoint.trim().length === 0) {
            return Promise.reject("Invalid JWKS URI found.");
        }

        return axios
            .get(jwksEndpoint)
            .then((response) => {
                if (response.status !== 200) {
                    return Promise.reject(new Error("Failed to load public keys from JWKS URI: " + jwksEndpoint));
                }

                const issuer = this._oidcProviderMetaData().issuer;
                const issuerFromURL = this.resolveWellKnownEndpoint().split("/.well-known")[0];

                // Return false if the issuer in the open id config doesn't match
                // the issuer in the well known endpoint URL.
                if (!issuer || issuer !== issuerFromURL) {
                    return Promise.resolve(false);
                }

                return CryptoHelper.getJWKForTheIdToken(idToken.split(".")[0], response.data.keys)
                    .then((jwk: KeyLike) => {
                        return CryptoHelper.isValidIdToken(
                            idToken,
                            jwk,
                            this._config().clientID,
                            issuer,
                            AuthenticationUtils.getAuthenticatedUser(idToken).username,
                            this._config().clockTolerance
                        );
                    })
                    .catch((error) => {
                        return Promise.reject(error);
                    });
            })
            .catch((error) => {
                return Promise.reject(error);
            });
    }

    public replaceTemplateTags(text: string): string {
        let scope = OIDC_SCOPE;

        if (this._config().scope && this._config().scope.length > 0) {
            if (!this._config().scope.includes(OIDC_SCOPE)) {
                this._config().scope.push(OIDC_SCOPE);
            }
            scope = this._config().scope.join(" ");
        }

        return text
            .replace(TOKEN_TAG, this._dataLayer.getSessionData().access_token)
            .replace(USERNAME_TAG,
                AuthenticationUtils.getAuthenticatedUser(this._dataLayer.getSessionData().id_token).username)
            .replace(SCOPE_TAG, scope)
            .replace(CLIENT_ID_TAG, this._config().clientID)
            .replace(CLIENT_SECRET_TAG, this._config().clientSecret);
    }

    public clearUserSessionData(): void {
        this._dataLayer.removeOIDCProviderMetaData();
        this._dataLayer.removeTemporaryData();
        this._dataLayer.removeSessionData();
    }
}
