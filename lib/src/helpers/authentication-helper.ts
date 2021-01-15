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

import { KeyLike } from "crypto";
import axios, { AxiosError, AxiosResponse } from "axios";
import {
    AUTHORIZATION_ENDPOINT,
    CLIENT_ID_TAG,
    CLIENT_SECRET_TAG,
    END_SESSION_ENDPOINT,
    JWKS_ENDPOINT,
    OIDC_SCOPE,
    OIDC_SESSION_IFRAME_ENDPOINT,
    REVOKE_TOKEN_ENDPOINT,
    SCOPE_TAG,
    SERVICE_RESOURCES,
    TOKEN_ENDPOINT,
    TOKEN_TAG,
    USERNAME_TAG
} from "../constants";
import { DataLayer } from "../data";
import { AsgardeoAuthException, AsgardeoAuthNetworkException } from "../exception";
import { AuthClientConfig, OIDCEndpointsInternal, OIDCProviderMetaData, TokenResponse } from "../models";
import { AuthenticationUtils, CryptoUtils } from "../utils";

export class AuthenticationHelper<T> {
    private _dataLayer: DataLayer<T>;
    private _config: () => Promise<AuthClientConfig>;
    private _oidcProviderMetaData: () => Promise<OIDCProviderMetaData>;

    public constructor(dataLayer: DataLayer<T>) {
        this._dataLayer = dataLayer;
        this._config = async () => await this._dataLayer.getConfigData();
        this._oidcProviderMetaData = async () => await this._dataLayer.getOIDCProviderMetaData();
    }

    public async resolveWellKnownEndpoint(): Promise<string> {
        const configData = await this._config();
        if (configData.wellKnownEndpoint) {
            return configData.serverOrigin + configData.wellKnownEndpoint;
        }

        return configData.serverOrigin + SERVICE_RESOURCES.wellKnownEndpoint;
    }

    public async resolveEndpoints(response: OIDCProviderMetaData): Promise<OIDCProviderMetaData> {
        const oidcProviderMetaData = {};
        const configData = await this._config();

        configData.endpoints &&
            Object.keys(configData.endpoints).forEach((endpointName: string) => {
                const camelCasedName = endpointName
                    .split("_")
                    .map((name: string, index: number) => {
                        if (index !== 0) {
                            return name[0].toUpperCase() + name.substring(1);
                        }

                        return name;
                    })
                    .join("");

                if (configData.overrideWellEndpointConfig && configData.endpoints[camelCasedName]) {
                    oidcProviderMetaData[camelCasedName] = configData.endpoints[camelCasedName];
                }
            });

        return { ...response, ...oidcProviderMetaData };
    }

    public async resolveFallbackEndpoints(): Promise<OIDCEndpointsInternal> {
        const oidcProviderMetaData = {};
        const configData = await this._config();

        configData.endpoints &&
            Object.keys(configData.endpoints).forEach((endpointName: string) => {
                const camelCasedName = endpointName
                    .split("_")
                    .map((name: string, index: number) => {
                        if (index !== 0) {
                            return name[0].toUpperCase() + name.substring(1);
                        }

                        return name;
                    })
                    .join("");

                oidcProviderMetaData[camelCasedName] = configData.endpoints[camelCasedName];
            });

        const defaultEndpoints = {
            [AUTHORIZATION_ENDPOINT]: configData.serverOrigin + SERVICE_RESOURCES.authorizationEndpoint,
            [END_SESSION_ENDPOINT]: configData.serverOrigin + SERVICE_RESOURCES.endSessionEndpoint,
            [JWKS_ENDPOINT]: configData.serverOrigin + SERVICE_RESOURCES.jwksUri,
            [OIDC_SESSION_IFRAME_ENDPOINT]: configData.serverOrigin + SERVICE_RESOURCES.checkSessionIframe,
            [REVOKE_TOKEN_ENDPOINT]: configData.serverOrigin + SERVICE_RESOURCES.revocationEndpoint,
            [TOKEN_ENDPOINT]: configData.serverOrigin + SERVICE_RESOURCES.tokenEndpoint
        };

        return { ...defaultEndpoints, ...oidcProviderMetaData };
    }

    public async validateIdToken(idToken: string): Promise<boolean> {
        const jwksEndpoint = (await this._dataLayer.getOIDCProviderMetaData()).jwks_uri;

        if (!jwksEndpoint || jwksEndpoint.trim().length === 0) {
            return Promise.reject(
                new AsgardeoAuthException(
                    "AUTH_HELPER-VIT-NF01",
                    "authentication-helper",
                    "validateIdToken",
                    "JWKS endpoint not found.",
                    "No JWKS endpoint was found in the OIDC provider meta data returned by the well-known endpoint " +
                        "or the JWKS endpoint passed to the SDK is empty."
                )
            );
        }

        return axios
            .get(jwksEndpoint)
            .then(async (response) => {
                if (response.status !== 200) {
                    return Promise.reject(
                        new AsgardeoAuthException(
                            "AUTH_HELPER-VIT-NR02",
                            "authentication-helper",
                            "validateIdToken",
                            "Invalid response status received for jwks request.",
                            "The request sent to get the jwks returned " + response.status + " , which is invalid."
                        )
                    );
                }

                const issuer = (await this._oidcProviderMetaData()).issuer;
                const issuerFromURL = (await this.resolveWellKnownEndpoint()).split("/.well-known")[0];

                // Return false if the issuer in the open id config doesn't match
                // the issuer in the well known endpoint URL.
                if (!issuer || issuer !== issuerFromURL) {
                    return Promise.resolve(false);
                }

                return CryptoUtils.getJWKForTheIdToken(idToken.split(".")[0], response.data.keys)
                    .then(async (jwk: KeyLike) => {
                        return CryptoUtils.isValidIdToken(
                            idToken,
                            jwk,
                            (await this._config()).clientID,
                            issuer,
                            AuthenticationUtils.getAuthenticatedUserInfo(idToken).username,
                            (await this._config()).clockTolerance
                        )
                            .then((response) => response)
                            .catch((error) => {
                                return Promise.reject(
                                    new AsgardeoAuthException(
                                        "AUTH_HELPER-VIT-ES03",
                                        "authentication-helper",
                                        "validateIdToken",
                                        null,
                                        null,
                                        error
                                    )
                                );
                            });
                    })
                    .catch((error) => {
                        return Promise.reject(
                            new AsgardeoAuthException(
                                "AUTH_HELPER-VIT-ES04",
                                "authentication-helper",
                                "validateIdToken",
                                null,
                                null,
                                error
                            )
                        );
                    });
            })
            .catch((error: AxiosError) => {
                return Promise.reject(
                    new AsgardeoAuthNetworkException(
                        "AUTH_HELPER-VIT-NR05",
                        "authentication-helper",
                        "validateIdToken",
                        "Request to jwks endpoint failed.",
                        "The request sent to get the jwks from the server failed.",
                        error?.code,
                        error?.message,
                        error?.response?.status,
                        error?.response?.data
                    )
                );
            });
    }

    public async replaceCustomGrantTemplateTags(text: string): Promise<string> {
        let scope = OIDC_SCOPE;
        const configData = await this._config();
        const sessionData = await this._dataLayer.getSessionData();

        if (configData.scope && configData.scope.length > 0) {
            if (!configData.scope.includes(OIDC_SCOPE)) {
                configData.scope.push(OIDC_SCOPE);
            }
            scope = configData.scope.join(" ");
        }

        return text
            .replace(TOKEN_TAG, sessionData.access_token)
            .replace(USERNAME_TAG, AuthenticationUtils.getAuthenticatedUserInfo(sessionData.id_token).username)
            .replace(SCOPE_TAG, scope)
            .replace(CLIENT_ID_TAG, configData.clientID)
            .replace(CLIENT_SECRET_TAG, configData.clientSecret);
    }

    public async clearUserSessionData(): Promise<void> {
        await this._dataLayer.removeOIDCProviderMetaData();
        await this._dataLayer.removeTemporaryData();
        await this._dataLayer.removeSessionData();
    }

    public async handleTokenResponse(response: AxiosResponse): Promise<TokenResponse> {
        if (response.status !== 200) {
            return Promise.reject(
                new AsgardeoAuthException(
                    "AUTH_HELPER-HTR-NR01",
                    "authentication-helper",
                    "handleTokenResponse",
                    "Invalid response status received for token request.",
                    "The request sent to get the token returned " + response.status + " , which is invalid."
                )
            );
        }
        if ((await this._config()).validateIDToken) {
            return this.validateIdToken(response.data.id_token)
                .then(async (valid) => {
                    if (valid) {
                        await this._dataLayer.setSessionData(response.data);

                        const tokenResponse: TokenResponse = {
                            accessToken: response.data.access_token,
                            expiresIn: response.data.expires_in,
                            idToken: response.data.id_token,
                            refreshToken: response.data.refresh_token,
                            scope: response.data.scope,
                            tokenType: response.data.token_type
                        };

                        return Promise.resolve(tokenResponse);
                    }

                    return Promise.reject(
                        new AsgardeoAuthException(
                            "AUTH_HELPER-HTR-IV02",
                            "authentication-helper",
                            "handleTokenResponse",
                            "The id token returned is not valid.",
                            "The id token returned has failed the validation check."
                        )
                    );
                })
                .catch((error) => {
                    return Promise.reject(
                        new AsgardeoAuthException(
                            "AUTH_HELPER-HAT-ES03",
                            "authentication-helper",
                            "handleTokenResponse",
                            null,
                            null,
                            error
                        )
                    );
                });
        } else {
            const tokenResponse: TokenResponse = {
                accessToken: response.data.access_token,
                expiresIn: response.data.expires_in,
                idToken: response.data.id_token,
                refreshToken: response.data.refresh_token,
                scope: response.data.scope,
                tokenType: response.data.token_type
            };
            await this._dataLayer.setSessionData(response.data);

            return Promise.resolve(tokenResponse);
        }
    }
}
