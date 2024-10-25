/**
 * Copyright (c) 2020, WSO2 LLC. (https://www.wso2.com). All Rights Reserved.
 *
 * WSO2 LLC. licenses this file to you under the Apache License,
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
    ISSUER,
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
    USERINFO_ENDPOINT,
    USERNAME_TAG
} from "../constants";
import { DataLayer } from "../data";
import { AsgardeoAuthException } from "../exception";
import {
    AuthClientConfig,
    AuthenticatedUserInfo,
    DecodedIDTokenPayload,
    JWKInterface,
    OIDCEndpointsInternal,
    OIDCProviderMetaData,
    RawTokenResponse,
    SessionData,
    StrictAuthClientConfig,
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

    public async resolveEndpoints(response: OIDCProviderMetaData): Promise<OIDCProviderMetaData> {
        const oidcProviderMetaData: OIDCProviderMetaData = {};
        const configData: StrictAuthClientConfig = await this._config();

        configData.endpoints &&
            Object.keys(configData.endpoints).forEach((endpointName: string) => {
                const snakeCasedName: string = endpointName
                    .replace(/[A-Z]/g, (letter: string) => `_${ letter.toLowerCase() }`);

                oidcProviderMetaData[ snakeCasedName ] = configData?.endpoints
                    ? configData.endpoints[ endpointName ]
                    : "";
            });

        return { ...response, ...oidcProviderMetaData };
    }

    public async resolveEndpointsExplicitly(): Promise<OIDCEndpointsInternal> {
        const oidcProviderMetaData: OIDCProviderMetaData = {};
        const configData: StrictAuthClientConfig = await this._config();

        const requiredEndpoints: string[] = [
            AUTHORIZATION_ENDPOINT,
            END_SESSION_ENDPOINT,
            JWKS_ENDPOINT,
            OIDC_SESSION_IFRAME_ENDPOINT,
            REVOKE_TOKEN_ENDPOINT,
            TOKEN_ENDPOINT,
            ISSUER,
            USERINFO_ENDPOINT
        ];

        const isRequiredEndpointsContains: boolean = configData.endpoints
            ? requiredEndpoints.every((reqEndpointName: string) => {
                return configData.endpoints
                    ? Object.keys(configData.endpoints).some((endpointName: string) => {
                        const snakeCasedName: string = endpointName.replace(
                            /[A-Z]/g,
                            (letter: string) => `_${ letter.toLowerCase() }`
                        );

                        return snakeCasedName === reqEndpointName;
                    })
                    : false;
            })
            : false;

        if (!isRequiredEndpointsContains) {
            throw new AsgardeoAuthException(
                "JS-AUTH_HELPER-REE-NF01",
                "Required endpoints missing",
                "Some or all of the required endpoints are missing in the object passed to the `endpoints` " +
                "attribute of the`AuthConfig` object."
            );
        }

        configData.endpoints &&
            Object.keys(configData.endpoints).forEach((endpointName: string) => {
                const snakeCasedName: string = endpointName
                    .replace(/[A-Z]/g, (letter: string) => `_${ letter.toLowerCase() }`);

                oidcProviderMetaData[ snakeCasedName ] = configData?.endpoints
                    ? configData.endpoints[ endpointName ]
                    : "";
            });

        return { ...oidcProviderMetaData };
    }

    public async resolveEndpointsByBaseURL(): Promise<OIDCEndpointsInternal> {
        const oidcProviderMetaData: OIDCEndpointsInternal = {};
        const configData: StrictAuthClientConfig = await this._config();

        const baseUrl: string = (configData as any).baseUrl;

        if (!baseUrl) {
            throw new AsgardeoAuthException(
                "JS-AUTH_HELPER_REBO-NF01",
                "Base URL not defined.",
                "Base URL is not defined in AuthClient config."
            );
        }

        configData.endpoints &&
            Object.keys(configData.endpoints).forEach((endpointName: string) => {
                const snakeCasedName: string = endpointName
                    .replace(/[A-Z]/g, (letter: string) => `_${ letter.toLowerCase() }`);

                oidcProviderMetaData[ snakeCasedName ] = configData?.endpoints
                    ? configData.endpoints[ endpointName ]
                    : "";
            });

        const defaultEndpoints: OIDCProviderMetaData = {
            [ AUTHORIZATION_ENDPOINT ]: `${baseUrl}${SERVICE_RESOURCES.authorizationEndpoint}`,
            [ END_SESSION_ENDPOINT ]: `${baseUrl}${SERVICE_RESOURCES.endSessionEndpoint}`,
            [ ISSUER ]: `${baseUrl}${SERVICE_RESOURCES.issuer}`,
            [ JWKS_ENDPOINT ]: `${baseUrl}${SERVICE_RESOURCES.jwksUri}`,
            [ OIDC_SESSION_IFRAME_ENDPOINT ]: `${baseUrl}${SERVICE_RESOURCES.checkSessionIframe}`,
            [ REVOKE_TOKEN_ENDPOINT ]: `${baseUrl}${SERVICE_RESOURCES.revocationEndpoint}`,
            [ TOKEN_ENDPOINT ]: `${baseUrl}${SERVICE_RESOURCES.tokenEndpoint}`,
            [ USERINFO_ENDPOINT ]: `${baseUrl}${SERVICE_RESOURCES.userinfoEndpoint}`
        };

        return { ...defaultEndpoints, ...oidcProviderMetaData };
    }

    public async validateIdToken(idToken: string): Promise<boolean> {
        const jwksEndpoint: string | undefined = (await this._dataLayer.getOIDCProviderMetaData()).jwks_uri;
        const configData: StrictAuthClientConfig = await this._config();

        if (!jwksEndpoint || jwksEndpoint.trim().length === 0) {
            throw new AsgardeoAuthException(
                "JS_AUTH_HELPER-VIT-NF01",
                "JWKS endpoint not found.",
                "No JWKS endpoint was found in the OIDC provider meta data returned by the well-known endpoint " +
                "or the JWKS endpoint passed to the SDK is empty."
            );
        }

        let response: Response;

        try {
            response = await fetch(jwksEndpoint, {
                credentials: configData.sendCookiesInRequests
                    ? FetchCredentialTypes.Include
                    : FetchCredentialTypes.SameOrigin
            });
        } catch (error: any) {
            throw new AsgardeoAuthException(
                "JS-AUTH_HELPER-VIT-NE02",
                "Request to jwks endpoint failed.",
                error ?? "The request sent to get the jwks from the server failed."
            );
        }

        if (response.status !== 200 || !response.ok) {
            throw new AsgardeoAuthException(
                "JS-AUTH_HELPER-VIT-HE03",
                `Invalid response status received for jwks request (${ response.statusText }).`,
                await response.json()
            );
        }

        const issuer: string | undefined = (await this._oidcProviderMetaData()).issuer;

        const { keys }: { keys: JWKInterface[]; } = await response.json();

        const jwk: any = await this._cryptoHelper.getJWKForTheIdToken(idToken.split(".")[ 0 ], keys);

        return this._cryptoHelper.isValidIdToken(
            idToken,
            jwk,
            (await this._config()).clientID,
            issuer ?? "",
            this._cryptoHelper.decodeIDToken(idToken).sub,
            (await this._config()).clockTolerance, 
            (await this._config()).validateIDTokenIssuer ?? true
        );
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
        let scope: string = OIDC_SCOPE;
        const configData: StrictAuthClientConfig = await this._config();
        const sessionData: SessionData = await this._dataLayer.getSessionData(userID);

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

    public async handleTokenResponse(response: Response, userID?: string): Promise<TokenResponse> {
        if (response.status !== 200 || !response.ok) {
            throw new AsgardeoAuthException(
                "JS-AUTH_HELPER-HTR-NE01",
                `Invalid response status received for token request (${ response.statusText }).`,
                await response.json()
            );
        }

        //Get the response in JSON
        const parsedResponse: RawTokenResponse = await response.json();

        parsedResponse.created_at = new Date().getTime();

        const shouldValidateIdToken: boolean | undefined = (await this._config()).validateIDToken;

        if (shouldValidateIdToken) {
            return this.validateIdToken(parsedResponse.id_token).then(async () => {
                await this._dataLayer.setSessionData(parsedResponse, userID);

                const tokenResponse: TokenResponse = {
                    accessToken: parsedResponse.access_token,
                    createdAt: parsedResponse.created_at,
                    expiresIn: parsedResponse.expires_in,
                    idToken: parsedResponse.id_token,
                    refreshToken: parsedResponse.refresh_token,
                    scope: parsedResponse.scope,
                    tokenType: parsedResponse.token_type
                };

                return Promise.resolve(tokenResponse);
            });
        } else {
            const tokenResponse: TokenResponse = {
                accessToken: parsedResponse.access_token,
                createdAt: parsedResponse.created_at,
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
     * @param userID - The userID to identify a user in a multi-user scenario.
     *
     * @returns The PKCE key.
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
