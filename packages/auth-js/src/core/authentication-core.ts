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

import axios, { AxiosError, AxiosRequestConfig, AxiosResponse } from "axios";
import {
    AUTHORIZATION_ENDPOINT,
    OIDC_SCOPE,
    OP_CONFIG_INITIATED,
    PKCE_CODE_VERIFIER,
    SESSION_STATE,
    SIGN_OUT_SUCCESS_PARAM
} from "../constants";
import { DataLayer } from "../data";
import { AsgardeoAuthException, AsgardeoAuthNetworkException } from "../exception";
import { AuthenticationHelper } from "../helpers";
import {
    AuthClientConfig,
    AuthorizationURLParams,
    BasicUserInfo,
    CustomGrantConfig,
    DecodedIDTokenPayload,
    OIDCEndpoints,
    OIDCProviderMetaData,
    TokenResponse
} from "../models";
import { AuthenticationUtils, CryptoUtils } from "../utils";

export class AuthenticationCore<T> {
    private _dataLayer: DataLayer<T>;
    private _config: () => AuthClientConfig;
    private _oidcProviderMetaData: () => OIDCProviderMetaData;
    private _authenticationHelper: AuthenticationHelper<T>;

    public constructor(dataLayer: DataLayer<T>) {
        this._authenticationHelper = new AuthenticationHelper(dataLayer);
        this._dataLayer = dataLayer;
        this._config = () => this._dataLayer.getConfigData();
        this._oidcProviderMetaData = () => this._dataLayer.getOIDCProviderMetaData();
    }

    public getAuthorizationURL(config?: AuthorizationURLParams): string {
        const authorizeEndpoint = this._dataLayer.getOIDCProviderMetaDataParameter(AUTHORIZATION_ENDPOINT) as string;

        if (!authorizeEndpoint || authorizeEndpoint.trim().length === 0) {
            throw new AsgardeoAuthException(
                "AUTH_CORE-GAU-NF01",
                "authentication-core",
                "getAuthorizationURL",
                "No authorization endpoint found.",
                "No authorization endpoint was found in the OIDC provider meta data from the well-known endpoint " +
                    "or the authorization endpoint passed to the SDK is empty."
            );
        }

        let authorizeRequest = authorizeEndpoint + "?response_type=code&client_id=" + this._config().clientID;

        let scope = OIDC_SCOPE;

        if (this._config().scope && this._config().scope.length > 0) {
            if (!this._config().scope.includes(OIDC_SCOPE)) {
                this._config().scope.push(OIDC_SCOPE);
            }
            scope = this._config().scope.join(" ");
        }

        authorizeRequest += "&scope=" + scope;
        const redirectURL = this._config().signInRedirectURL;
        authorizeRequest += "&redirect_uri=" + redirectURL;

        if (this._config().responseMode) {
            authorizeRequest += "&response_mode=" + this._config().responseMode;
        }

        if (this._config().enablePKCE) {
            const codeVerifier = CryptoUtils.getCodeVerifier();
            const codeChallenge = CryptoUtils.getCodeChallenge(codeVerifier);
            this._dataLayer.setTemporaryDataParameter(PKCE_CODE_VERIFIER, codeVerifier);
            authorizeRequest += "&code_challenge_method=S256&code_challenge=" + codeChallenge;
        }

        if (this._config().prompt) {
            authorizeRequest += "&prompt=" + this._config().prompt;
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

    public requestAccessToken(authorizationCode: string, sessionState: string): Promise<TokenResponse> {
        const tokenEndpoint = this._oidcProviderMetaData().token_endpoint;

        if (!tokenEndpoint || tokenEndpoint.trim().length === 0) {
            return Promise.reject(
                new AsgardeoAuthException(
                    "AUTH_CORE-RAT1-NF01",
                    "authentication-core",
                    "requestAccessToken",
                    "Token endpoint not found.",
                    "No token endpoint was found in the OIDC provider meta data returned by the well-known endpoint " +
                        "or the token endpoint passed to the SDK is empty."
                )
            );
        }

        this._dataLayer.setSessionDataParameter(SESSION_STATE, sessionState);

        const body = [];
        body.push(`client_id=${this._config().clientID}`);

        if (this._config().clientSecret && this._config().clientSecret.trim().length > 0) {
            body.push(`client_secret=${this._config().clientSecret}`);
        }

        const code = authorizationCode;
        body.push(`code=${code}`);

        body.push("grant_type=authorization_code");
        body.push(`redirect_uri=${this._config().signInRedirectURL}`);

        if (this._config().enablePKCE) {
            body.push(`code_verifier=${this._dataLayer.getTemporaryDataParameter(PKCE_CODE_VERIFIER)}`);
            this._dataLayer.removeTemporaryDataParameter(PKCE_CODE_VERIFIER);
        }

        return axios
            .post(tokenEndpoint, body.join("&"), { headers: AuthenticationUtils.getTokenRequestHeaders() })
            .then((response) => {
                return this._authenticationHelper
                    .handleTokenResponse(response)
                    .then((response: TokenResponse) => response)
                    .catch((error) => {
                        return Promise.reject(
                            new AsgardeoAuthException(
                                "AUTH_CORE-RAT1-ES02",
                                "authentication-core",
                                "requestAccessToken",
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
                        "AUTH_CORE-RAT1-NR03",
                        "authentication-core",
                        "requestAccessToken",
                        "Requesting access token failed",
                        "The request to get the access token from the server failed.",
                        error?.code,
                        error?.message,
                        error?.response?.status,
                        error?.response?.data
                    )
                );
            });
    }

    public refreshAccessToken(): Promise<TokenResponse> {
        const tokenEndpoint = this._oidcProviderMetaData().token_endpoint;

        if (!this._dataLayer.getSessionData().refresh_token) {
            return Promise.reject(
                new AsgardeoAuthException(
                    "AUTH_CORE-RAT2-NF01",
                    "authentication-core",
                    "refreshAccessToken",
                    "No refresh token found.",
                    "There was no refresh token found. The identity server doesn't return a " +
                        "refresh token if the refresh token grant is not enabled."
                )
            );
        }

        if (!tokenEndpoint || tokenEndpoint.trim().length === 0) {
            return Promise.reject(
                new AsgardeoAuthException(
                    "AUTH_CORE-RAT2-NF02",
                    "authentication-core",
                    "refreshAccessToken",
                    "No refresh token endpoint found.",
                    "No refresh token endpoint was in the OIDC provider meta data returned by the well-known " +
                        "endpoint or the refresh token endpoint passed to the SDK is empty."
                )
            );
        }

        const body = [];
        body.push(`client_id=${this._config().clientID}`);
        body.push(`refresh_token=${this._dataLayer.getSessionData().refresh_token}`);
        body.push("grant_type=refresh_token");

        if (this._config().clientSecret && this._config().clientSecret.trim().length > 0) {
            body.push(`client_secret=${this._config().clientSecret}`);
        }

        return axios
            .post(tokenEndpoint, body.join("&"), { headers: AuthenticationUtils.getTokenRequestHeaders() })
            .then((response) => {
                return this._authenticationHelper
                    .handleTokenResponse(response)
                    .then((response: TokenResponse) => response)
                    .catch((error) => {
                        return Promise.reject(
                            new AsgardeoAuthException(
                                "AUTH_CORE-RAT2-ES03",
                                "authentication-core",
                                "refreshAccessToken",
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
                        "AUTH_CORE-RAT2-NR03",
                        "authentication-core",
                        "refreshAccessToken",
                        "Refresh access token request failed.",
                        "The request to refresh the access token failed.",
                        error?.code,
                        error?.message,
                        error?.response?.status,
                        error?.response?.data
                    )
                );
            });
    }

    public revokeAccessToken(): Promise<AxiosResponse> {
        const revokeTokenEndpoint = this._oidcProviderMetaData().revocation_endpoint;

        if (!revokeTokenEndpoint || revokeTokenEndpoint.trim().length === 0) {
            return Promise.reject(
                new AsgardeoAuthException(
                    "AUTH_CORE-RAT3-NF01",
                    "authentication-core",
                    "revokeAccessToken",
                    "No revoke access token endpoint found.",
                    "No revoke access token endpoint was found in the OIDC provider meta data returned by " +
                        "the well-known endpoint or the revoke access token endpoint passed to the SDK is empty."
                )
            );
        }

        const body = [];
        body.push(`client_id=${this._config().clientID}`);
        body.push(`token=${this._dataLayer.getSessionData().access_token}`);
        body.push("token_type_hint=access_token");

        return axios
            .post(revokeTokenEndpoint, body.join("&"), {
                headers: AuthenticationUtils.getTokenRequestHeaders(),
                withCredentials: true
            })
            .then((response) => {
                if (response.status !== 200) {
                    return Promise.reject(
                        new AsgardeoAuthException(
                            "AUTH_CORE-RAT3-NR02",
                            "authentication-core",
                            "revokeAccessToken",
                            "Invalid response status received for revoke access token request.",
                            "The request sent to revoke the access token returned " +
                                response.status +
                                " , which is invalid."
                        )
                    );
                }

                this._authenticationHelper.clearUserSessionData();

                return Promise.resolve(response);
            })
            .catch((error: AxiosError) => {
                return Promise.reject(
                    new AsgardeoAuthNetworkException(
                        "AUTH_CORE-RAT3-NR03",
                        "authentication-core",
                        "revokeAccessToken",
                        "The request to revoke access token failed.",
                        "The request sent to revoke the access token failed.",
                        error?.code,
                        error?.message,
                        error?.response?.status,
                        error?.response?.data
                    )
                );
            });
    }

    public requestCustomGrant = (customGrantParams: CustomGrantConfig): Promise<TokenResponse | AxiosResponse> => {
        if (
            !this._oidcProviderMetaData().token_endpoint ||
            this._oidcProviderMetaData().token_endpoint.trim().length === 0
        ) {
            return Promise.reject(
                new AsgardeoAuthException(
                    "AUTH_CORE-RCG-NF01",
                    "authentication-core",
                    "requestCustomGrant",
                    "Token endpoint not found.",
                    "No token endpoint was found in the OIDC provider meta data returned by the well-known endpoint " +
                        "or the token endpoint passed to the SDK is empty."
                )
            );
        }

        let data: string = "";

        Object.entries(customGrantParams.data).map(([key, value], index: number) => {
            const newValue = this._authenticationHelper.replaceCustomGrantTemplateTags(value as string);
            data += `${key}=${newValue}${index !== Object.entries(customGrantParams.data).length - 1 ? "&" : ""}`;
        });

        const requestConfig: AxiosRequestConfig = {
            data: data,
            headers: {
                ...AuthenticationUtils.getTokenRequestHeaders()
            },
            method: "POST",
            url: this._oidcProviderMetaData().token_endpoint
        };

        if (customGrantParams.attachToken) {
            requestConfig.headers = {
                ...requestConfig.headers,
                Authorization: `Bearer ${this._dataLayer.getSessionData().access_token}`
            };
        }

        return axios(requestConfig)
            .then(
                (response: AxiosResponse): Promise<AxiosResponse | TokenResponse> => {
                    if (response.status !== 200) {
                        return Promise.reject(
                            new AsgardeoAuthException(
                                "AUTH_CORE-RCG-NR02",
                                "authentication-core",
                                "requestCustomGrant",
                                "Invalid response status received for the custom grant request.",
                                "The request sent to get the custom grant returned " +
                                    response.status +
                                    " , which is invalid."
                            )
                        );
                    }

                    if (customGrantParams.returnsSession) {
                        return this._authenticationHelper
                            .handleTokenResponse(response)
                            .then((response: TokenResponse) => response)
                            .catch((error) => {
                                return Promise.reject(
                                    new AsgardeoAuthException(
                                        "AUTH_CORE-RCG-ES03",
                                        "authentication-core",
                                        "requestCustomGrant",
                                        null,
                                        null,
                                        error
                                    )
                                );
                            });
                    } else {
                        return Promise.resolve(response);
                    }
                }
            )
            .catch((error: AxiosError) => {
                return Promise.reject(
                    new AsgardeoAuthNetworkException(
                        "AUTH_CORE-RCG-NR04",
                        "authentication-core",
                        "requestCustomGrant",
                        "The custom grant request failed.",
                        "The request sent to get teh custom grant failed.",
                        error?.code,
                        error?.message,
                        error?.response?.status,
                        error?.response?.data
                    )
                );
            });
    };

    public getBasicUserInfo(): BasicUserInfo {
        const sessionData = this._dataLayer.getSessionData();
        const authenticatedUser = AuthenticationUtils.getAuthenticatedUserInfo(sessionData?.id_token);
        return {
            allowedScopes: sessionData.scope,
            displayName: authenticatedUser.displayName,
            email: authenticatedUser.email,
            sessionState: sessionData.session_state,
            tenantDomain: authenticatedUser.tenantDomain,
            username: authenticatedUser.username
        };
    }

    public getDecodedIDToken(): DecodedIDTokenPayload {
        const idToken = this._dataLayer.getSessionData().id_token;
        const payload: DecodedIDTokenPayload = CryptoUtils.decodeIDToken(idToken);

        return payload;
    }

    public getOIDCProviderMetaData(forceInit: boolean): Promise<boolean> {
        if (!forceInit && this._dataLayer.getTemporaryDataParameter(OP_CONFIG_INITIATED)) {
            return Promise.resolve(true);
        }

        const wellKnownEndpoint = this._authenticationHelper.resolveWellKnownEndpoint();

        return axios
            .get(wellKnownEndpoint)
            .then((response: { data: OIDCProviderMetaData; status: number }) => {
                if (response.status !== 200) {
                    return Promise.reject(
                        new AsgardeoAuthException(
                            "AUTH_CORE-GOPM-NR01",
                            "authentication-core",
                            "getOIDCProviderMetaData",
                            "Invalid response status received for OIDC provider meta data request.",
                            "The request sent to the well-known endpoint to get the OIDC provider meta data returned " +
                                response.status +
                                " , which is invalid."
                        )
                    );
                }

                this._dataLayer.setOIDCProviderMetaData(this._authenticationHelper.resolveEndpoints(response.data));
                this._dataLayer.setTemporaryDataParameter(OP_CONFIG_INITIATED, true);

                return Promise.resolve(true);
            })
            .catch(() => {
                this._dataLayer.setOIDCProviderMetaData(this._authenticationHelper.resolveFallbackEndpoints());
                this._dataLayer.setTemporaryDataParameter(OP_CONFIG_INITIATED, true);

                return Promise.resolve(true);
            });
    }

    public getOIDCServiceEndpoints(): OIDCEndpoints {
        return {
            authorizationEndpoint: this._oidcProviderMetaData().authorization_endpoint,
            checkSessionIframe: this._oidcProviderMetaData().check_session_iframe,
            endSessionEndpoint: this._oidcProviderMetaData().end_session_endpoint,
            introspectionEndpoint: this._oidcProviderMetaData().introspection_endpoint,
            issuer: this._oidcProviderMetaData().issuer,
            jwksUri: this._oidcProviderMetaData().jwks_uri,
            registrationEndpoint: this._oidcProviderMetaData().registration_endpoint,
            revocationEndpoint: this._oidcProviderMetaData().revocation_endpoint,
            tokenEndpoint: this._oidcProviderMetaData().token_endpoint,
            userinfoEndpoint: this._oidcProviderMetaData().userinfo_endpoint,
            wellKnownEndpoint: this._authenticationHelper.resolveWellKnownEndpoint()
        };
    }

    public getSignOutURL(): string {
        const logoutEndpoint = this._oidcProviderMetaData()?.end_session_endpoint;

        if (!logoutEndpoint || logoutEndpoint.trim().length === 0) {
            throw new AsgardeoAuthException(
                "AUTH_CORE-GSOU-NF01",
                "authentication-core",
                "getSignOutURL",
                "Sign-out endpoint not found.",
                "No sign-out endpoint was found in the OIDC provider meta data returned by the well-known endpoint " +
                    "or the sign-out endpoint passed to the SDK is empty."
            );
        }

        const idToken = this._dataLayer.getSessionData()?.id_token;

        if (!idToken || idToken.trim().length === 0) {
            throw new AsgardeoAuthException(
                "AUTH_CORE-GSOU-NF02",
                "authentication-core",
                "getSignOutURL",
                "ID token n0t found.",
                "No ID token could be found. Either the session information is lost or you have not signed in."
            );
        }

        const callbackURL = this._config()?.signOutRedirectURL ?? this._config()?.signInRedirectURL;

        if (!callbackURL || callbackURL.trim().length === 0) {
            throw new AsgardeoAuthException(
                "AUTH_CORE-GSOU-NF03",
                "authentication-core",
                "getSignOutURL",
                "No sign-out redirect URL found.",
                "The sign-out redirect URL cannot be found or the URL passed to the SDK is empty. " +
                    "No sign-in redirect URL has been found either. "
            );
        }

        const logoutCallback =
            `${logoutEndpoint}?` +
            `id_token_hint=${idToken}` +
            `&post_logout_redirect_uri=${callbackURL}&state=` +
            SIGN_OUT_SUCCESS_PARAM;

        return logoutCallback;
    }

    public signOut(): string {
        const signOutURL = this.getSignOutURL();
        this._authenticationHelper.clearUserSessionData();

        return signOutURL;
    }

    public getAccessToken(): string {
        return this._dataLayer.getSessionData()?.access_token;
    }

    public isAuthenticated(): boolean {
        return Boolean(this.getAccessToken());
    }

    public getPKCECode(): string {
        return this._dataLayer.getTemporaryDataParameter(PKCE_CODE_VERIFIER) as string;
    }

    public setPKCECode(pkce: string): void {
        return this._dataLayer.setTemporaryDataParameter(PKCE_CODE_VERIFIER, pkce);
    }

    public updateConfig(config: Partial<AuthClientConfig<T>>): void {
        this._dataLayer.setConfigData(config);
    }
}
