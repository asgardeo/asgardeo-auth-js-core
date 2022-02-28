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

import { CryptoHelper } from "./crypto-helper";
import {
    AUTHORIZATION_ENDPOINT,
    CLIENT_ID_TAG,
    CLIENT_SECRET_TAG,
    END_SESSION_ENDPOINT,
    FetchCredentialTypes,
    JWKS_ENDPOINT,
    OIDC_SCOPE,
    OIDC_SESSION_IFRAME_ENDPOINT,
    PKCE_CODE_VERIFIER,
    PKCE_SEPARATOR,
    REVOKE_TOKEN_ENDPOINT,
    SCOPE_TAG,
    SERVICE_RESOURCES,
    TOKEN_ENDPOINT,
    TOKEN_TAG,
    USERNAME_TAG
} from "../constants";
import { DataLayer } from "../data";
import { AsgardeoAuthException, AsgardeoAuthNetworkException } from "../exception";
import {
    AuthClientConfig,
    AuthenticatedUserInfo,
    DecodedIDTokenPayload,
    FetchError,
    FetchResponse,
    OIDCEndpointsInternal,
    OIDCProviderMetaData,
    TemporaryData,
    TokenResponse
} from "../models";
import { AuthenticationUtils } from "../utils";

export class AuthenticationHelper<T> {
    private _dataLayer: DataLayer<T>;
    private _config: () => Promise<AuthClientConfig>;
    private _oidcProviderMetaData: () => Promise<OIDCProviderMetaData>;
    private _cryptoHelper: CryptoHelper;

    public constructor(dataLayer: DataLayer<T>, cryptoHelper: CryptoHelper) {
        this._dataLayer = dataLayer;
        this._config = async () => await this._dataLayer.getConfigData();
        this._oidcProviderMetaData = async () => await this._dataLayer.getOIDCProviderMetaData();
        this._cryptoHelper = cryptoHelper;
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

        if (configData.overrideWellEndpointConfig) {
            configData.endpoints &&
                Object.keys(configData.endpoints).forEach((endpointName: string) => {
                    const snakeCasedName = endpointName.replace(/[A-Z]/g, (letter) => `_${ letter.toLowerCase() }`);
                    oidcProviderMetaData[ snakeCasedName ] = configData?.endpoints
                        ? configData.endpoints[ endpointName ]
                        : "";
                });
        }

        return { ...response, ...oidcProviderMetaData };
    }

    public async resolveFallbackEndpoints(): Promise<OIDCEndpointsInternal> {
        const oidcProviderMetaData = {};
        const configData = await this._config();

        configData.endpoints &&
            Object.keys(configData.endpoints).forEach((endpointName: string) => {
                const snakeCasedName = endpointName.replace(/[A-Z]/g, (letter) => `_${ letter.toLowerCase() }`);
                oidcProviderMetaData[ snakeCasedName ] = configData?.endpoints ? configData.endpoints[ endpointName ] : "";
            });

        const defaultEndpoints = {
            [ AUTHORIZATION_ENDPOINT ]: configData.serverOrigin + SERVICE_RESOURCES.authorizationEndpoint,
            [ END_SESSION_ENDPOINT ]: configData.serverOrigin + SERVICE_RESOURCES.endSessionEndpoint,
            [ JWKS_ENDPOINT ]: configData.serverOrigin + SERVICE_RESOURCES.jwksUri,
            [ OIDC_SESSION_IFRAME_ENDPOINT ]: configData.serverOrigin + SERVICE_RESOURCES.checkSessionIframe,
            [ REVOKE_TOKEN_ENDPOINT ]: configData.serverOrigin + SERVICE_RESOURCES.revocationEndpoint,
            [ TOKEN_ENDPOINT ]: configData.serverOrigin + SERVICE_RESOURCES.tokenEndpoint
        };

        return { ...oidcProviderMetaData, ...defaultEndpoints };
    }

    public async validateIdToken(idToken: string): Promise<boolean> {
        const jwksEndpoint = (await this._dataLayer.getOIDCProviderMetaData()).jwks_uri;
        const configData = await this._config();

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

        // eslint-disable-next-line max-len
        return fetch(jwksEndpoint, {
            credentials: configData.sendCookiesInRequests
                ? FetchCredentialTypes.Include
                : FetchCredentialTypes.SameOrigin
        })
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
                const issuerFromURL = (await this.resolveWellKnownEndpoint()).split("/.well-known")[ 0 ];

                // Return false if the issuer in the open id config doesn't match
                // the issuer in the well known endpoint URL.
                if (!issuer || issuer !== issuerFromURL) {
                    return Promise.resolve(false);
                }
                const parsedResponse = await response.json();

                return this._cryptoHelper
                    .getJWKForTheIdToken(idToken.split(".")[ 0 ], parsedResponse.keys)
                    .then(async (jwk: any) => {
                        return this._cryptoHelper
                            .isValidIdToken(
                                idToken,
                                jwk,
                                (await this._config()).clientID,
                                issuer,
                                this._cryptoHelper.decodeIDToken(idToken).sub,
                                (await this._config()).clockTolerance
                            )
                            .then((response) => response)
                            .catch((error) => {
                                return Promise.reject(
                                    new AsgardeoAuthException(
                                        "AUTH_HELPER-VIT-ES03",
                                        "authentication-helper",
                                        "validateIdToken",
                                        undefined,
                                        undefined,
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
                                undefined,
                                undefined,
                                error
                            )
                        );
                    });
            })
            .catch((error: FetchError) => {
                return Promise.reject(
                    new AsgardeoAuthNetworkException(
                        "AUTH_HELPER-VIT-NR05",
                        "authentication-helper",
                        "validateIdToken",
                        "Request to jwks endpoint failed.",
                        "The request sent to get the jwks from the server failed.",
                        error?.code ?? "",
                        error?.message,
                        error?.response?.status,
                        error?.response?.body
                    )
                );
            });
    }

    public getAuthenticatedUserInfo(idToken: string): AuthenticatedUserInfo {
        const payload: DecodedIDTokenPayload = this._cryptoHelper.decodeIDToken(idToken);
        const tenantDomain: string = AuthenticationUtils.getTenantDomainFromIdTokenPayload(payload);
        const username: string = payload?.username ?? "";
        const givenName: string = payload.given_name ?? "";
        const familyName: string = payload.family_name ?? "";
        const fullName: string =
            givenName && familyName
                ? `${ givenName } ${ familyName }`
                : givenName
                    ? givenName
                    : familyName
                        ? familyName
                        : "";
        const displayName: string = payload.preferred_username ?? fullName;

        return {
            displayName: displayName,
            tenantDomain,
            username: username,
            ...AuthenticationUtils.filterClaimsFromIDTokenPayload(payload)
        };
    }

    public async replaceCustomGrantTemplateTags(text: string, userID?: string): Promise<string> {
        let scope = OIDC_SCOPE;
        const configData = await this._config();
        const sessionData = await this._dataLayer.getSessionData(userID);

        if (configData.scope && configData.scope.length > 0) {
            if (!configData.scope.includes(OIDC_SCOPE)) {
                configData.scope.push(OIDC_SCOPE);
            }
            scope = configData.scope.join(" ");
        }

        return text
            .replace(TOKEN_TAG, sessionData.access_token)
            .replace(USERNAME_TAG, this.getAuthenticatedUserInfo(sessionData.id_token).username)
            .replace(SCOPE_TAG, scope)
            .replace(CLIENT_ID_TAG, configData.clientID)
            .replace(CLIENT_SECRET_TAG, configData.clientSecret ?? "");
    }

    public async clearUserSessionData(userID?: string): Promise<void> {
        await this._dataLayer.removeTemporaryData(userID);
        await this._dataLayer.removeSessionData(userID);
    }

    public async handleTokenResponse(response: FetchResponse, userID?: string): Promise<TokenResponse> {
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

        //Get the response in JSON
        const parsedResponse = await response.json();

        if ((await this._config()).validateIDToken) {
            return this.validateIdToken(parsedResponse.id_token)
                .then(async (valid) => {
                    if (valid) {
                        await this._dataLayer.setSessionData(parsedResponse, userID);

                        const tokenResponse: TokenResponse = {
                            accessToken: parsedResponse.access_token,
                            expiresIn: parsedResponse.expires_in,
                            idToken: parsedResponse.id_token,
                            refreshToken: parsedResponse.refresh_token,
                            scope: parsedResponse.scope,
                            tokenType: parsedResponse.token_type
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
                            undefined,
                            undefined,
                            error
                        )
                    );
                });
        } else {
            const tokenResponse: TokenResponse = {
                accessToken: parsedResponse.access_token,
                expiresIn: parsedResponse.expires_in,
                idToken: parsedResponse.id_token,
                refreshToken: parsedResponse.refresh_token,
                scope: parsedResponse.scope,
                tokenType: parsedResponse.token_type
            };
            await this._dataLayer.setSessionData(parsedResponse, userID);

            return Promise.resolve(tokenResponse);
        }
    }

    /**
     * This generates a PKCE key with the right index value.
     *
     * @param {string} userID The userID to identify a user in a multi-user scenario.
     *
     * @returns {string} The PKCE key.
     */
    public async generatePKCEKey(userID?: string): Promise<string> {
        const tempData: TemporaryData = await this._dataLayer.getTemporaryData(userID);
        const keys: string[] = [];

        Object.keys(tempData).forEach((key: string) => {
            if (key.startsWith(PKCE_CODE_VERIFIER)) {
                keys.push(key);
            }
        });

        const lastKey: string | undefined = keys.sort().pop();
        const index: number = parseInt(lastKey?.split(PKCE_SEPARATOR)[ 1 ] ?? "-1");

        return `${ PKCE_CODE_VERIFIER }${ PKCE_SEPARATOR }${ index + 1 }`;
    }
}
