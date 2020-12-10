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

import { OIDC_SCOPE, AUTHORIZATION_ENDPOINT, PKCE_CODE_VERIFIER, SESSION_STATE, SIGNED_IN, OP_CONFIG_INITIATED, SERVICE_RESOURCES, LOGOUT_SUCCESS } from "../constants";
import { getCodeVerifier, getCodeChallenge, getJWKForTheIdToken, isValidIdToken, decodeIDToken } from "../utils";
import { Store } from "./models/store";
import { OIDCProviderMetaData, TokenResponseInterface, CustomGrantRequestParams, UserInfo, DecodedIdTokenPayloadInterface, OpenIDConfig, OIDCEndpointConstantsInterface, SendAuthorizationRequestParameter } from "../models";
import { AuthenticationUtils } from "./authenitcation-utils";
import { KeyLike } from "jose/webcrypto/types";
import axios, { AxiosResponse, AxiosRequestConfig } from "axios";
import { Config } from "./models/config";

export class AuthenticationCore {
    private _store: Store;
    private _config: Config;
    private _oidcProviderMetaData: OIDCProviderMetaData;
    private _authenticationUtils: AuthenticationUtils;

    public constructor(store: Store) {
        this._authenticationUtils = new AuthenticationUtils(store);
        this._store = store;
        this._config = this._store.getConfigData();
        this._oidcProviderMetaData = this._store.getOIDCProviderMetaData();
    }
    public sendAuthorizationRequest(config?: SendAuthorizationRequestParameter): string {
        const authorizeEndpoint = this._store.getOIDCProviderMetaDataParameter(AUTHORIZATION_ENDPOINT) as string;

        if (!authorizeEndpoint || authorizeEndpoint.trim().length === 0) {
            throw Error("Invalid authorize endpoint found.");
        }

        let authorizeRequest = authorizeEndpoint + "?response_type=code&client_id=" + this._config.clientID;

        let scope = OIDC_SCOPE;

        if (this._config.scope && this._config.scope.length > 0) {
            if (!this._config.scope.includes(OIDC_SCOPE)) {
                this._config.scope.push(OIDC_SCOPE);
            }
            scope = this._config.scope.join(" ");
        }

        authorizeRequest += "&scope=" + scope;
        authorizeRequest += "&redirect_uri=" + this._config.signInRedirectURL;

        if (this._config.responseMode) {
            authorizeRequest += "&response_mode=" + this._config.responseMode;
        }

        if (this._config.enablePKCE) {
            const codeVerifier = getCodeVerifier();
            const codeChallenge = getCodeChallenge(codeVerifier);
            this._store.setTemporaryDataParameter(PKCE_CODE_VERIFIER, codeVerifier);
            authorizeRequest += "&code_challenge_method=S256&code_challenge=" + codeChallenge;
        }

        if (this._config.prompt) {
            authorizeRequest += "&prompt=" + this._config.prompt;
        }

        const customParams = config;
        if (customParams) {
            for (const [key, value] of Object.entries(customParams)) {
                if (key != "" && value != "") {
                    authorizeRequest += "&" + key + "=" + value;
                }
            }
        }

        return authorizeRequest;
    }

    public sendTokenRequest(authorizationCode: string, sessionState: string): Promise<TokenResponseInterface> {
        const tokenEndpoint = this._oidcProviderMetaData.token_endpoint;

        if (!tokenEndpoint || tokenEndpoint.trim().length === 0) {
            return Promise.reject(new Error("Invalid token endpoint found."));
        }

        this._store.setSessionDataParameter(SESSION_STATE, sessionState);

        const body = [];
        body.push(`client_id=${this._config.clientID}`);

        if (this._config.clientSecret && this._config.clientSecret.trim().length > 0) {
            body.push(`client_secret=${this._config.clientSecret}`);
        }

        const code = authorizationCode;
        body.push(`code=${code}`);

        body.push("grant_type=authorization_code");
        body.push(`redirect_uri=${this._config.signInRedirectURL}`);

        if (this._config.enablePKCE) {
            body.push(`code_verifier=${this._store.getTemporaryDataParameter(PKCE_CODE_VERIFIER)}`);
            this._store.removeTemporaryDataParameter(PKCE_CODE_VERIFIER);
        }

        return axios
            .post(tokenEndpoint, body.join("&"), { headers: this._authenticationUtils.getTokenRequestHeaders() })
            .then((response) => {
                if (response.status !== 200) {
                    return Promise.reject(
                        new Error("Invalid status code received in the token response: " + response.status)
                    );
                }

                if (this._config.validateIDToken) {
                    return this._authenticationUtils
                        .validateIdToken(response.data.id_token)
                        .then((valid) => {
                            if (valid) {
                                this._store.setSessionData(response.data);

                                const tokenResponse: TokenResponseInterface = {
                                    accessToken: response.data.access_token,
                                    expiresIn: response.data.expires_in,
                                    idToken: response.data.id_token,
                                    refreshToken: response.data.refresh_token,
                                    scope: response.data.scope,
                                    tokenType: response.data.token_type
                                };

                                return Promise.resolve(tokenResponse);
                            }

                            return Promise.reject("Invalid id_token in the token response: " + response.data.id_token);
                        })
                        .catch((error) => {
                            return Promise.reject(error);
                        });
                } else {
                    const tokenResponse: TokenResponseInterface = {
                        accessToken: response.data.access_token,
                        expiresIn: response.data.expires_in,
                        idToken: response.data.id_token,
                        refreshToken: response.data.refresh_token,
                        scope: response.data.scope,
                        tokenType: response.data.token_type
                    };
                    this._store.setSessionData(response.data);

                    return Promise.resolve(tokenResponse);
                }
            })
            .catch((error) => {
                return Promise.reject(error);
            });
    }

    public sendRefreshTokenRequest(): Promise<TokenResponseInterface> {
        const tokenEndpoint = this._oidcProviderMetaData.token_endpoint;

        if (!this._store.getSessionData().refresh_token) {
            return Promise.reject("No refresh token found");
        }

        if (!tokenEndpoint || tokenEndpoint.trim().length === 0) {
            return Promise.reject("Invalid token endpoint found.");
        }

        const body = [];
        body.push(`client_id=${this._config.clientID}`);
        body.push(`refresh_token=${this._store.getSessionData().refresh_token}`);
        body.push("grant_type=refresh_token");

        if (this._config.clientSecret && this._config.clientSecret.trim().length > 0) {
            body.push(`client_secret=${this._config.clientSecret}`);
        }

        return axios
            .post(tokenEndpoint, body.join("&"), { headers: this._authenticationUtils.getTokenRequestHeaders() })
            .then((response) => {
                if (response.status !== 200) {
                    return Promise.reject(
                        new Error("Invalid status code received in the refresh token response: " + response.status)
                    );
                }

                if (this._config.validateIDToken) {
                    return this._authenticationUtils.validateIdToken(response.data.id_token).then((valid) => {
                        if (valid) {
                            const tokenResponse: TokenResponseInterface = {
                                accessToken: response.data.access_token,
                                expiresIn: response.data.expires_in,
                                idToken: response.data.id_token,
                                refreshToken: response.data.refresh_token,
                                scope: response.data.scope,
                                tokenType: response.data.token_type
                            };

                            this._store.setSessionData(response.data);

                            return Promise.resolve(tokenResponse);
                        }

                        return Promise.reject("Invalid id_token in the token response: " + response.data.id_token);
                    });
                } else {
                    const tokenResponse: TokenResponseInterface = {
                        accessToken: response.data.access_token,
                        expiresIn: response.data.expires_in,
                        idToken: response.data.id_token,
                        refreshToken: response.data.refresh_token,
                        scope: response.data.scope,
                        tokenType: response.data.token_type
                    };

                    this._store.setSessionData(response.data);

                    return Promise.resolve(tokenResponse);
                }
            })
            .catch((error) => {
                return Promise.reject(error);
            });
    }

    public sendRevokeTokenRequest(): Promise<AxiosResponse> {
        const revokeTokenEndpoint = this._oidcProviderMetaData.revocation_endpoint;

        if (!revokeTokenEndpoint || revokeTokenEndpoint.trim().length === 0) {
            return Promise.reject("Invalid revoke token endpoint found.");
        }

        const body = [];
        body.push(`client_id=${this._config.clientID}`);
        body.push(`token=${this._store.getSessionData().access_token}`);
        body.push("token_type_hint=access_token");

        return axios
            .post(revokeTokenEndpoint, body.join("&"), {
                headers: this._authenticationUtils.getTokenRequestHeaders(),
                withCredentials: true
            })
            .then((response) => {
                if (response.status !== 200) {
                    return Promise.reject(
                        new Error("Invalid status code received in the revoke token response: " + response.status)
                    );
                }

                this._authenticationUtils.clearUserSessionData();

                return Promise.resolve(response);
            })
            .catch((error) => {
                return Promise.reject(error);
            });
    }

    public customGrant = (
        customGrantParams: CustomGrantRequestParams
    ): Promise<TokenResponseInterface | AxiosResponse> => {
        if (
            !this._oidcProviderMetaData.token_endpoint ||
            this._oidcProviderMetaData.token_endpoint.trim().length === 0
        ) {
            return Promise.reject(new Error("Invalid token endpoint found."));
        }

        let data: string = "";

        Object.entries(customGrantParams.data).map(([key, value], index: number) => {
            const newValue = this._authenticationUtils.replaceTemplateTags(value as string);
            data += `${key}=${newValue}${index !== Object.entries(customGrantParams.data).length - 1 ? "&" : ""}`;
        });

        const requestConfig: AxiosRequestConfig = {
            data: data,
            headers: {
                ...this._authenticationUtils.getTokenRequestHeaders()
            },
            method: "POST",
            url: this._oidcProviderMetaData.token_endpoint
        };

        if (customGrantParams.attachToken) {
            requestConfig.headers = {
                ...requestConfig.headers,
                Authorization: `Bearer ${this._store.getSessionData().access_token}`
            };
        }

        return axios(requestConfig)
            .then(
                (response: AxiosResponse): Promise<AxiosResponse | TokenResponseInterface> => {
                    if (response.status !== 200) {
                        return Promise.reject(
                            new Error("Invalid status code received in the token response: " + response.status)
                        );
                    }

                    if (customGrantParams.returnsSession) {
                        if (this._config.validateIDToken) {
                            return this._authenticationUtils.validateIdToken(response.data.id_token).then((valid) => {
                                if (valid) {
                                    const tokenResponse: TokenResponseInterface = {
                                        accessToken: response.data.access_token,
                                        expiresIn: response.data.expires_in,
                                        idToken: response.data.id_token,
                                        refreshToken: response.data.refresh_token,
                                        scope: response.data.scope,
                                        tokenType: response.data.token_type
                                    };

                                    this._store.setSessionData(response.data);

                                        return Promise.resolve(tokenResponse);

                                }

                                return Promise.reject(
                                    new Error("Invalid id_token in the token response: " + response.data.id_token)
                                );
                            });
                        } else {
                            const tokenResponse: TokenResponseInterface = {
                                accessToken: response.data.access_token,
                                expiresIn: response.data.expires_in,
                                idToken: response.data.id_token,
                                refreshToken: response.data.refresh_token,
                                scope: response.data.scope,
                                tokenType: response.data.token_type
                            };

                            this._store.setSessionData(response.data);

                                return Promise.resolve(tokenResponse);

                        }
                    } else {
                        return Promise.resolve(response);
                    }
                }
            )
            .catch((error: any) => {
                return Promise.reject(error);
            });
    };

    public getUserInfo(): UserInfo {
        const sessionData = this._store.getSessionData();
        const authenticatedUser = this._authenticationUtils.getAuthenticatedUser(sessionData.id_token);
        return {
            allowedScopes: sessionData.scope,
            displayName: authenticatedUser.displayName,
            email: authenticatedUser.email,
            sessionState: sessionData.session_state,
            tenantDomain: authenticatedUser.tenantDomain,
            username: authenticatedUser.username
        };
    }

    public getDecodedIDToken(): DecodedIdTokenPayloadInterface {
        const idToken = this._store.getSessionData().id_token;
        const payload: DecodedIdTokenPayloadInterface = decodeIDToken(idToken);

        return payload;
    }

    public initOPConfiguration(forceInit: boolean): Promise<any> {
        if (!forceInit && this._store.getTemporaryDataParameter(OP_CONFIG_INITIATED)) {
            return Promise.resolve();
        }

        const serverHost = this._config.serverOrigin;
        const wellKnownEndpoint = this._authenticationUtils.resolveWellKnownEndpoint();

        return axios
            .get(wellKnownEndpoint)
            .then((response: { data: OpenIDConfig; status: number }) => {
                if (response.status !== 200) {
                    return Promise.reject(
                        new Error("Failed to load OpenID provider configuration from: " + wellKnownEndpoint)
                    );
                }

                this._store.setOIDCProviderMetaData(this._authenticationUtils.resolveEndpoints(response.data));
                this._store.setTemporaryDataParameter(OP_CONFIG_INITIATED, true);

                return Promise.resolve(
                    "Initialized OpenID Provider configuration from: " +
                        serverHost +
                        SERVICE_RESOURCES.wellKnownEndpoint
                );
            })
            .catch(() => {
                this._store.setOIDCProviderMetaData(this._authenticationUtils.resolveFallbackEndpoints());
                this._store.setTemporaryDataParameter(OP_CONFIG_INITIATED, true);

                return Promise.resolve(
                    new Error(
                        "Initialized OpenID Provider configuration from default configuration." +
                            "Because failed to access wellknown endpoint: " +
                            serverHost +
                            SERVICE_RESOURCES.wellKnownEndpoint
                    )
                );
            });
    }

    public getServiceEndpoints(): OIDCEndpointConstantsInterface {
        return {
            authorizationEndpoint: this._oidcProviderMetaData.authorization_endpoint,
            checkSessionIframe: this._oidcProviderMetaData.check_session_iframe,
            endSessionEndpoint: this._oidcProviderMetaData.end_session_endpoint,
            introspectionEndpoint: this._oidcProviderMetaData.introspection_endpoint,
            issuer: this._oidcProviderMetaData.issuer,
            jwksUri: this._oidcProviderMetaData.jwks_uri,
            registrationEndpoint: this._oidcProviderMetaData.registration_endpoint,
            revocationEndpoint: this._oidcProviderMetaData.revocation_endpoint,
            tokenEndpoint: this._oidcProviderMetaData.token_endpoint,
            userinfoEndpoint: this._oidcProviderMetaData.userinfo_endpoint,
            wellKnownEndpoint: this._authenticationUtils.resolveWellKnownEndpoint()
        };
    }

    public getSignOutURL(): string {
        const logoutEndpoint = this._oidcProviderMetaData.end_session_endpoint;

        if (!logoutEndpoint || logoutEndpoint.trim().length === 0) {
            throw Error("No logout endpoint found in the session.");
        }

        const idToken = this._store.getSessionData().id_token;

        if (!idToken || idToken.trim().length === 0) {
            throw Error("Invalid id_token found in the session.");
        }

        const callbackURL = this._config.signOutRedirectURL ?? this._config.signInRedirectURL;

        if (!callbackURL || callbackURL.trim().length === 0) {
            throw Error("No callback URL found in the session.");
        }

        this._authenticationUtils.clearUserSessionData();

        const logoutCallback =
            `${logoutEndpoint}?` +
            `id_token_hint=${idToken}` +
            `&post_logout_redirect_uri=${callbackURL}&state=` +
            LOGOUT_SUCCESS;

        return logoutCallback;


    }

    public getRefreshToken(): string{
        return this._store.getSessionData().access_token;
    }
}
