import { Store } from "./models/store";
import { AuthenticatedUserInterface, DecodedIdTokenPayloadInterface, TokenRequestHeader, OIDCProviderMetaData, OIDCEndpointsInternal } from "../models";
import { SERVICE_RESOURCES } from "..";
import { decodeIDToken, getJWKForTheIdToken, isValidIdToken } from "../utils/crypto";
import axios from "axios";
import { KeyLike } from "crypto";
import { OIDC_SCOPE, TOKEN_TAG, USERNAME_TAG, SCOPE_TAG, CLIENT_ID_TAG, CLIENT_SECRET_TAG, USERNAME, ACCESS_TOKEN, AUTHORIZATION_ENDPOINT, OIDC_SESSION_IFRAME_ENDPOINT, END_SESSION_ENDPOINT, JWKS_ENDPOINT, REVOKE_TOKEN_ENDPOINT, TOKEN_ENDPOINT } from "../constants";
import { Config } from "./models/config";
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
export class AuthenticationUtils {
    private _store: Store;
    private _config: Config;
    private _oidcProviderMetaData: OIDCProviderMetaData;

    public constructor(store:Store) {
        this._store = store;
        this._config = this._store.getConfigData();
        this._oidcProviderMetaData = this._store.getOIDCProviderMetaData();
    }

    public resolveWellKnownEndpoint(): string {
        if (this._config.wellKnownEndpoint) {
            return this._config.serverOrigin + this._config.wellKnownEndpoint;
        }

        return this._config.serverOrigin + SERVICE_RESOURCES.wellKnownEndpoint;
    }

    public resolveEndpoints(response: OIDCProviderMetaData): OIDCProviderMetaData {
        const oidcProviderMetaData = {};
        this._config.endpoints &&
            Object.keys(this._config.endpoints).forEach((endpointName: string) => {
                const camelCasedName = endpointName
                    .split("_")
                    .map((name: string, index: number) => {
                        if (index !== 0) {
                            return name[0].toUpperCase() + name.substring(1);
                        }

                        return name;
                    })
                    .join("");

                if (this._config.overrideWellEndpointConfig && this._config.endpoints[camelCasedName]) {
                    oidcProviderMetaData[camelCasedName] = this._config.endpoints[camelCasedName];
                }
            });

        return { ...response, ...oidcProviderMetaData };
    }

    public resolveFallbackEndpoints(): OIDCEndpointsInternal {
        const oidcProviderMetaData = {};
        this._config.endpoints &&
            Object.keys(this._config.endpoints).forEach((endpointName: string) => {
                const camelCasedName = endpointName
                    .split("_")
                    .map((name: string, index: number) => {
                        if (index !== 0) {
                            return name[0].toUpperCase() + name.substring(1);
                        }

                        return name;
                    })
                    .join("");

                    oidcProviderMetaData[camelCasedName] = this._config.endpoints[camelCasedName];
            });

        const defaultEndpoints = {
            [ AUTHORIZATION_ENDPOINT ]: SERVICE_RESOURCES.authorizationEndpoint,
            [ END_SESSION_ENDPOINT ]: SERVICE_RESOURCES.endSessionEndpoint,
            [ JWKS_ENDPOINT ]: SERVICE_RESOURCES.jwksUri,
            [ OIDC_SESSION_IFRAME_ENDPOINT ]: SERVICE_RESOURCES.checkSessionIframe,
            [ REVOKE_TOKEN_ENDPOINT ]: SERVICE_RESOURCES.revocationEndpoint,
            [ TOKEN_ENDPOINT ]: SERVICE_RESOURCES.tokenEndpoint
        };

        return { ...defaultEndpoints, ...oidcProviderMetaData };
    }

    public getAuthenticatedUser(idToken: string): AuthenticatedUserInterface {
        const payload: DecodedIdTokenPayloadInterface = decodeIDToken(idToken);
        const emailAddress: string = payload.email ? payload.email : null;
        const tenantDomain: string = this.getTenantDomainFromIdTokenPayload(payload);

        return {
            displayName: payload.preferred_username ? payload.preferred_username : payload.sub,
            email: emailAddress,
            tenantDomain,
            username: payload.sub
        };
    }

    public getTenantDomainFromIdTokenPayload = (
        payload: DecodedIdTokenPayloadInterface,
        uidSeparator: string = "@"
    ): string => {
        // If the `tenant_domain` claim is available in the ID token payload, give precedence.
        if (payload.tenant_domain) {
            return payload.tenant_domain;
        }

        // Try to extract the tenant domain from the `sub` claim.
        const uid = payload.sub;
        const tokens = uid.split(uidSeparator);

        return tokens[tokens.length - 1];
    };

    public getTokenRequestHeaders(): TokenRequestHeader {
        return {
            Accept: "application/json",
            "Content-Type": "application/x-www-form-urlencoded"
        };
    }

    public validateIdToken(idToken: string): Promise<any> {
        const jwksEndpoint = this._store.getOIDCProviderMetaData().jwks_uri;

        if (!jwksEndpoint || jwksEndpoint.trim().length === 0) {
            return Promise.reject("Invalid JWKS URI found.");
        }

        return axios
            .get(jwksEndpoint)
            .then((response) => {
                if (response.status !== 200) {
                    return Promise.reject(new Error("Failed to load public keys from JWKS URI: " + jwksEndpoint));
                }

                const issuer = this._oidcProviderMetaData.issuer;
                const issuerFromURL = this.resolveWellKnownEndpoint().split("/.well-known")[0];

                // Return false if the issuer in the open id config doesn't match
                // the issuer in the well known endpoint URL.
                if (!issuer || issuer !== issuerFromURL) {
                    return Promise.resolve(false);
                }

                return getJWKForTheIdToken(idToken.split(".")[0], response.data.keys)
                    .then((jwk: KeyLike) => {
                        return isValidIdToken(
                            idToken,
                            jwk,
                            this._config.clientID,
                            issuer,
                            this.getAuthenticatedUser(idToken).username,
                            this._config.clockTolerance
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

        if (this._config.scope && this._config.scope.length > 0) {
            if (!this._config.scope.includes(OIDC_SCOPE)) {
                this._config.scope.push(OIDC_SCOPE);
            }
            scope = this._config.scope.join(" ");
        }

        return text
            .replace(TOKEN_TAG, this._store.getSessionData().access_token)
            .replace(USERNAME_TAG, this.getAuthenticatedUser(this._store.getSessionData().id_token).username)
            .replace(SCOPE_TAG, scope)
            .replace(CLIENT_ID_TAG, this._config.clientID)
            .replace(CLIENT_SECRET_TAG, this._config.clientSecret);
    }

    public clearUserSessionData(): void {
        this._store.removeOIDCProviderMetaData();
        this._store.removeTemporaryData();
        this._store.removeSessionData();
    }
}
