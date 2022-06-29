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
import {
    AUTHORIZATION_ENDPOINT,
    FetchCredentialTypes,
    OIDC_SCOPE,
    OP_CONFIG_INITIATED,
    SESSION_STATE,
    SIGN_OUT_SUCCESS_PARAM,
    STATE
} from "../constants";
import { DataLayer } from "../data";
import { AsgardeoAuthException } from "../exception";
import { AuthenticationHelper, CryptoHelper } from "../helpers";
import {
    AuthClientConfig,
    AuthorizationURLParams,
    BasicUserInfo,
    CryptoUtils,
    CustomGrantConfig,
    DecodedIDTokenPayload,
    FetchRequestConfig,
    FetchResponse,
    OIDCEndpoints,
    OIDCProviderMetaData,
    TokenResponse
} from "../models";
import { AuthenticationUtils } from "../utils";

export class AuthenticationCore<T> {
    private _dataLayer: DataLayer<T>;
    private _config: () => Promise<AuthClientConfig>;
    private _oidcProviderMetaData: () => Promise<OIDCProviderMetaData>;
    private _authenticationHelper: AuthenticationHelper<T>;
    private _cryptoUtils: CryptoUtils;
    private _cryptoHelper: CryptoHelper;

    public constructor(dataLayer: DataLayer<T>, cryptoUtils: CryptoUtils) {
        this._cryptoUtils = cryptoUtils;
        this._cryptoHelper = new CryptoHelper(cryptoUtils);
        this._authenticationHelper = new AuthenticationHelper(dataLayer, this._cryptoHelper);
        this._dataLayer = dataLayer;
        this._config = async () => await this._dataLayer.getConfigData();
        this._oidcProviderMetaData = async () => await this._dataLayer.getOIDCProviderMetaData();
    }

    public async getAuthorizationURL(config?: AuthorizationURLParams, userID?: string): Promise<string> {
        const authorizeEndpoint = (await this._dataLayer.getOIDCProviderMetaDataParameter(
            AUTHORIZATION_ENDPOINT
        )) as string;

        const configData = await this._config();

        if (!authorizeEndpoint || authorizeEndpoint.trim().length === 0) {
            throw new AsgardeoAuthException(
                "JS-AUTH_CORE-GAU-NF01",
                "No authorization endpoint found.",
                "No authorization endpoint was found in the OIDC provider meta data from the well-known endpoint " +
                "or the authorization endpoint passed to the SDK is empty."
            );
        }

        const authorizeRequest = new URL(authorizeEndpoint);

        const authorizeRequestParams = new Map();

        authorizeRequestParams.set("response_type", "code");
        authorizeRequestParams.set("client_id", configData.clientID);

        let scope = OIDC_SCOPE;

        if (configData.scope && configData.scope.length > 0) {
            if (!configData.scope.includes(OIDC_SCOPE)) {
                configData.scope.push(OIDC_SCOPE);
            }
            scope = configData.scope.join(" ");
        }

        authorizeRequestParams.set("scope", scope);
        authorizeRequestParams.set("redirect_uri", configData.signInRedirectURL);

        if (configData.responseMode) {
            authorizeRequestParams.set("response_mode", configData.responseMode);
        }

        const pkceKey: string = await this._authenticationHelper.generatePKCEKey(userID);

        if (configData.enablePKCE) {
            const codeVerifier = this._cryptoHelper?.getCodeVerifier();
            const codeChallenge = this._cryptoHelper?.getCodeChallenge(codeVerifier);

            await this._dataLayer.setTemporaryDataParameter(pkceKey, codeVerifier, userID);
            authorizeRequestParams.set("code_challenge_method", "S256");
            authorizeRequestParams.set("code_challenge", codeChallenge);
        }

        if (configData.prompt) {
            authorizeRequestParams.set("prompt", configData.prompt);
        }

        const customParams = config;
        if (customParams) {
            for (const [ key, value ] of Object.entries(customParams)) {
                if (key != "" && value != "" && key !== STATE) {
                    const snakeCasedKey = key.replace(/[A-Z]/g, (letter) => `_${ letter.toLowerCase() }`);
                    authorizeRequestParams.set(snakeCasedKey, value.toString());
                }
            }
        }

        authorizeRequestParams.set(
            STATE,
            AuthenticationUtils.generateStateParamForRequestCorrelation(
                pkceKey,
                customParams ? customParams[ STATE ]?.toString() : ""
            )
        );

        for (const [key, value] of authorizeRequestParams.entries()) {
            authorizeRequest.searchParams.append(key, value);
        }

        return authorizeRequest.toString();
    }

    public async requestAccessToken(
        authorizationCode: string,
        sessionState: string,
        state: string,
        userID?: string
    ): Promise<TokenResponse> {
        const tokenEndpoint = (await this._oidcProviderMetaData()).token_endpoint;
        const configData = await this._config();

        if (!tokenEndpoint || tokenEndpoint.trim().length === 0) {
            throw new AsgardeoAuthException(
                "JS-AUTH_CORE-RAT1-NF01",
                "Token endpoint not found.",
                "No token endpoint was found in the OIDC provider meta data returned by the well-known endpoint " +
                "or the token endpoint passed to the SDK is empty."
            );
        }

        sessionState && (await this._dataLayer.setSessionDataParameter(SESSION_STATE, sessionState, userID));

        const body: string[] = [];
        body.push(`client_id=${ configData.clientID }`);

        if (configData.clientSecret && configData.clientSecret.trim().length > 0) {
            body.push(`client_secret=${ configData.clientSecret }`);
        }

        const code = authorizationCode;
        body.push(`code=${ code }`);

        body.push("grant_type=authorization_code");
        body.push(`redirect_uri=${ configData.signInRedirectURL }`);

        if (configData.enablePKCE) {
            body.push(
                `code_verifier=${ await this._dataLayer.getTemporaryDataParameter(
                    AuthenticationUtils.extractPKCEKeyFromStateParam(state),
                    userID
                ) }`
            );

            await this._dataLayer.removeTemporaryDataParameter(
                AuthenticationUtils.extractPKCEKeyFromStateParam(state),
                userID
            );
        }

        let tokenResponse: Response;
        try {
            tokenResponse = await fetch(tokenEndpoint, {
                body: body.join("&"),
                credentials: configData.sendCookiesInRequests
                    ? FetchCredentialTypes.Include
                    : FetchCredentialTypes.SameOrigin,
                headers: new Headers(AuthenticationUtils.getTokenRequestHeaders()),
                method: "POST"
            });
        } catch (error: any) {
            throw new AsgardeoAuthException(
                "JS-AUTH_CORE-RAT1-NE02",
                "Requesting access token failed",
                error ?? "The request to get the access token from the server failed."
            );
        }

        if (!tokenResponse.ok) {
            throw new AsgardeoAuthException(
                "JS-AUTH_CORE-RAT1-HE03",
                `Requesting access token failed with ${tokenResponse.statusText}`,
                await tokenResponse.json()
            );
        }

        return await this._authenticationHelper.handleTokenResponse(tokenResponse, userID);
    }

    public async refreshAccessToken(userID?: string): Promise<TokenResponse> {
        const tokenEndpoint = (await this._oidcProviderMetaData()).token_endpoint;
        const configData = await this._config();
        const sessionData = await this._dataLayer.getSessionData(userID);

        if (!sessionData.refresh_token) {
            throw new AsgardeoAuthException(
                "JS-AUTH_CORE-RAT2-NF01",
                "No refresh token found.",
                "There was no refresh token found. Asgardeo doesn't return a " +
                "refresh token if the refresh token grant is not enabled."
            );
        }

        if (!tokenEndpoint || tokenEndpoint.trim().length === 0) {
            throw new AsgardeoAuthException(
                "JS-AUTH_CORE-RAT2-NF02",
                "No refresh token endpoint found.",
                "No refresh token endpoint was in the OIDC provider meta data returned by the well-known " +
                "endpoint or the refresh token endpoint passed to the SDK is empty."
            );
        }

        const body: string[] = [];
        body.push(`client_id=${ configData.clientID }`);
        body.push(`refresh_token=${ sessionData.refresh_token }`);
        body.push("grant_type=refresh_token");

        if (configData.clientSecret && configData.clientSecret.trim().length > 0) {
            body.push(`client_secret=${ configData.clientSecret }`);
        }

        let tokenResponse: Response;

        try {
            tokenResponse = await fetch(tokenEndpoint, {
                body: body.join("&"),
                credentials: configData.sendCookiesInRequests
                    ? FetchCredentialTypes.Include
                    : FetchCredentialTypes.SameOrigin,
                headers: new Headers(AuthenticationUtils.getTokenRequestHeaders()),
                method: "POST"
            });
        } catch (error: any) {
            throw new AsgardeoAuthException(
                "JS-AUTH_CORE-RAT2-NR03",
                "Refresh access token request failed.",
                error ?? "The request to refresh the access token failed."
            );
        }

        if (!tokenResponse.ok) {
            throw new AsgardeoAuthException(
                "JS-AUTH_CORE-RAT2-HE04",
                `Refreshing access token failed with ${tokenResponse.statusText}`,
                await tokenResponse.json()
            );
        }

        return this._authenticationHelper.handleTokenResponse(tokenResponse, userID);
    }

    public async revokeAccessToken(userID?: string): Promise<FetchResponse> {
        const revokeTokenEndpoint = (await this._oidcProviderMetaData()).revocation_endpoint;
        const configData = await this._config();

        if (!revokeTokenEndpoint || revokeTokenEndpoint.trim().length === 0) {
            throw new AsgardeoAuthException(
                "JS-AUTH_CORE-RAT3-NF01",
                "No revoke access token endpoint found.",
                "No revoke access token endpoint was found in the OIDC provider meta data returned by " +
                "the well-known endpoint or the revoke access token endpoint passed to the SDK is empty."
            );
        }

        const body: string[] = [];
        body.push(`client_id=${ configData.clientID }`);
        body.push(`token=${ (await this._dataLayer.getSessionData(userID)).access_token }`);
        body.push("token_type_hint=access_token");

        let response: Response;
        try {
            response = await fetch(revokeTokenEndpoint, {
                body: body.join("&"),
                credentials: configData.sendCookiesInRequests
                    ? FetchCredentialTypes.Include
                    : FetchCredentialTypes.SameOrigin,
                headers: new Headers(AuthenticationUtils.getTokenRequestHeaders()),
                method: "POST"
            });
        } catch (error: any) {
            throw new AsgardeoAuthException(
                "JS-AUTH_CORE-RAT3-NE02",
                "The request to revoke access token failed.",
                error ?? "The request sent to revoke the access token failed."
            );
        }

        if (response.status !== 200 || !response.ok) {
            throw new AsgardeoAuthException(
                "JS-AUTH_CORE-RAT3-HE03",
                `Invalid response status received for revoke access token request (${response.statusText}).`,
                await response.json()
            );
        }

        this._authenticationHelper.clearUserSessionData(userID);

        return Promise.resolve(response);
    }

    public async requestCustomGrant(
        customGrantParams: CustomGrantConfig,
        userID?: string
    ): Promise<TokenResponse | FetchResponse> {
        const oidcProviderMetadata = await this._oidcProviderMetaData();
        const configData = await this._config();

        let tokenEndpoint;
        if (customGrantParams.tokenEndpoint && customGrantParams.tokenEndpoint.trim().length !== 0) {
            tokenEndpoint = customGrantParams.tokenEndpoint;
        } else {
            tokenEndpoint = oidcProviderMetadata.token_endpoint;
        }

        if (!tokenEndpoint || tokenEndpoint.trim().length === 0) {
            throw new AsgardeoAuthException(
                "JS-AUTH_CORE-RCG-NF01",
                "Token endpoint not found.",
                "No token endpoint was found in the OIDC provider meta data returned by the well-known endpoint " +
                "or the token endpoint passed to the SDK is empty."
            );
        }

        const data: string[] = await Promise.all(
            Object.entries(customGrantParams.data).map(async ([ key, value ]) => {
                const newValue = await this._authenticationHelper.replaceCustomGrantTemplateTags(
                    value as string,
                    userID
                );
                return `${ key }=${ newValue }`;
            })
        );

        let requestHeaders = {
            ...AuthenticationUtils.getTokenRequestHeaders()
        };

        if (customGrantParams.attachToken) {
            requestHeaders = {
                ...requestHeaders,
                Authorization: `Bearer ${ (await this._dataLayer.getSessionData(userID)).access_token }`
            };
        }

        const requestConfig: FetchRequestConfig = {
            body: data.join("&"),
            credentials: configData.sendCookiesInRequests
                ? FetchCredentialTypes.Include
                : FetchCredentialTypes.SameOrigin,
            headers: new Headers(requestHeaders),
            method: "POST"
        };

        let response: Response;
        try {
            response = await fetch(tokenEndpoint, requestConfig);
        } catch (error: any) {
            throw new AsgardeoAuthException(
                "JS-AUTH_CORE-RCG-NE02",
                "The custom grant request failed.",
                error ?? "The request sent to get the custom grant failed."
            );
        }

        if (response.status !== 200 || !response.ok) {
            throw new AsgardeoAuthException(
                "JS-AUTH_CORE-RCG-HE03",
                `Invalid response status received for the custom grant request. (${response.statusText})`,
                await response.json()
            );
        }

        if (customGrantParams.returnsSession) {
            return this._authenticationHelper.handleTokenResponse(response, userID);
        } else {
            return Promise.resolve(await response.json());
        }
    }

    public async getBasicUserInfo(userID?: string): Promise<BasicUserInfo> {
        const sessionData = await this._dataLayer.getSessionData(userID);
        const authenticatedUser = this._authenticationHelper.getAuthenticatedUserInfo(sessionData?.id_token);

        let basicUserInfo: BasicUserInfo = {
            allowedScopes: sessionData.scope,
            sessionState: sessionData.session_state
        };

        Object.keys(authenticatedUser).forEach((key) => {
            if (
                authenticatedUser[ key ] === undefined ||
                authenticatedUser[ key ] === "" ||
                authenticatedUser[ key ] === null
            ) {
                delete authenticatedUser[ key ];
            }
        });

        basicUserInfo = { ...basicUserInfo, ...authenticatedUser };

        return basicUserInfo;
    }

    public async getDecodedIDToken(userID?: string): Promise<DecodedIDTokenPayload> {
        const idToken = (await this._dataLayer.getSessionData(userID)).id_token;
        const payload: DecodedIDTokenPayload = this._cryptoHelper.decodeIDToken(idToken);

        return payload;
    }

    public async getCryptoHelper(): Promise<CryptoHelper> {
        return this._cryptoHelper;
    }

    public async getIDToken(userID?: string): Promise<string> {
        return (await this._dataLayer.getSessionData(userID)).id_token;
    }

    public async getOIDCProviderMetaData(forceInit: boolean): Promise<void> {
        const configData = await this._config();
        if (!forceInit && (await this._dataLayer.getTemporaryDataParameter(OP_CONFIG_INITIATED))) {
            return Promise.resolve();
        }

        const wellKnownEndpoint = (configData as any).wellKnownEndpoint;

        if (wellKnownEndpoint) {

            let response: Response;

            try {
                response = await fetch(wellKnownEndpoint);
                if (response.status !== 200 || !response.ok) {
                    throw new Error();
                }
            } catch {
                throw new AsgardeoAuthException(
                    "JS-AUTH_CORE-GOPMD-HE01",
                    "Invalid well-known response",
                    "The well known endpoint response has been failed with an error."
                );
            }

            await this._dataLayer.setOIDCProviderMetaData(
                await this._authenticationHelper.resolveEndpoints(await response.json())
            );
            await this._dataLayer.setTemporaryDataParameter(OP_CONFIG_INITIATED, true);

            return Promise.resolve();
        } else if ((configData as any).baseUrl) {
            try {
                await this._dataLayer.setOIDCProviderMetaData(
                    await this._authenticationHelper.resolveEndpointsByBaseURL());
            } catch (error: any) {
                throw new AsgardeoAuthException(
                    "JS-AUTH_CORE-GOPMD-IV02",
                    "Resolving endpoints failed.",
                    error ?? "Resolving endpoints by base url failed."
                );
            }
            await this._dataLayer.setTemporaryDataParameter(OP_CONFIG_INITIATED, true);

            return Promise.resolve();
        }  else {
            try {
                await this._dataLayer.setOIDCProviderMetaData(
                    await this._authenticationHelper.resolveEndpointsExplicitly());
            } catch (error: any) {
                throw new AsgardeoAuthException(
                    "JS-AUTH_CORE-GOPMD-IV03",
                    "Resolving endpoints failed.",
                    error ?? "Resolving endpoints by explicitly failed."
                );
            }
            await this._dataLayer.setTemporaryDataParameter(OP_CONFIG_INITIATED, true);
            
            return Promise.resolve();
        }
    }

    public async getOIDCServiceEndpoints(): Promise<OIDCEndpoints> {
        const oidcProviderMetaData = await this._oidcProviderMetaData();

        return {
            authorizationEndpoint: oidcProviderMetaData.authorization_endpoint ?? "",
            checkSessionIframe: oidcProviderMetaData.check_session_iframe ?? "",
            endSessionEndpoint: oidcProviderMetaData.end_session_endpoint ?? "",
            introspectionEndpoint: oidcProviderMetaData.introspection_endpoint ?? "",
            issuer: oidcProviderMetaData.issuer ?? "",
            jwksUri: oidcProviderMetaData.jwks_uri ?? "",
            registrationEndpoint: oidcProviderMetaData.registration_endpoint ?? "",
            revocationEndpoint: oidcProviderMetaData.revocation_endpoint ?? "",
            tokenEndpoint: oidcProviderMetaData.token_endpoint ?? "",
            userinfoEndpoint: oidcProviderMetaData.userinfo_endpoint ?? ""
        };
    }

    public async getSignOutURL(userID?: string): Promise<string> {
        const logoutEndpoint = (await this._oidcProviderMetaData())?.end_session_endpoint;
        const configData = await this._config();

        if (!logoutEndpoint || logoutEndpoint.trim().length === 0) {
            throw new AsgardeoAuthException(
                "JS-AUTH_CORE-GSOU-NF01",
                "Sign-out endpoint not found.",
                "No sign-out endpoint was found in the OIDC provider meta data returned by the well-known endpoint " +
                "or the sign-out endpoint passed to the SDK is empty."
            );
        }

        const idToken = (await this._dataLayer.getSessionData(userID))?.id_token;

        if (!idToken || idToken.trim().length === 0) {
            throw new AsgardeoAuthException(
                "JS-AUTH_CORE-GSOU-NF02",
                "ID token not found.",
                "No ID token could be found. Either the session information is lost or you have not signed in."
            );
        }

        const callbackURL = configData?.signOutRedirectURL ?? configData?.signInRedirectURL;

        if (!callbackURL || callbackURL.trim().length === 0) {
            throw new AsgardeoAuthException(
                "JS-AUTH_CORE-GSOU-NF03",
                "No sign-out redirect URL found.",
                "The sign-out redirect URL cannot be found or the URL passed to the SDK is empty. " +
                "No sign-in redirect URL has been found either. "
            );
        }

        const logoutCallback =
            `${ logoutEndpoint }?` +
            `id_token_hint=${ idToken }` +
            `&post_logout_redirect_uri=${ callbackURL }&state=` +
            SIGN_OUT_SUCCESS_PARAM;

        return logoutCallback;
    }

    public async clearUserSessionData(userID?: string): Promise<void> {
        await this._authenticationHelper.clearUserSessionData(userID);
    }

    public async getAccessToken(userID?: string): Promise<string> {
        return (await this._dataLayer.getSessionData(userID))?.access_token;
    }

    public async isAuthenticated(userID?: string): Promise<boolean> {
        return Boolean(await this.getAccessToken(userID));
    }

    public async getPKCECode(state: string, userID?: string): Promise<string> {
        return (await this._dataLayer.getTemporaryDataParameter(
            AuthenticationUtils.extractPKCEKeyFromStateParam(state),
            userID
        )) as string;
    }

    public async setPKCECode(pkce: string, state: string, userID?: string): Promise<void> {
        return await this._dataLayer.setTemporaryDataParameter(
            AuthenticationUtils.extractPKCEKeyFromStateParam(state),
            pkce,
            userID
        );
    }

    public async updateConfig(config: Partial<AuthClientConfig<T>>): Promise<void> {
        await this._dataLayer.setConfigData(config);
        await this.getOIDCProviderMetaData(true);
    }
}
