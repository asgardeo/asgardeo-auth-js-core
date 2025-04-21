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
    AuthenticatedUserInfo,
    AuthorizationURLParams,
    BasicUserInfo,
    CryptoUtils,
    CustomGrantConfig,
    DecodedIDTokenPayload,
    FetchRequestConfig,
    FetchResponse,
    OIDCEndpoints,
    OIDCProviderMetaData,
    SessionData,
    StrictAuthClientConfig,
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

    public async getAuthorizationURLParams(
        config?: AuthorizationURLParams,
        userID?: string
    ): Promise<Map<string, string>> {
        const configData: StrictAuthClientConfig = await this._config();
  
        const authorizeRequestParams: Map<string, string> = new Map<
        string,
        string
      >();
  
        authorizeRequestParams.set("response_type", "code");
        authorizeRequestParams.set("client_id", configData.clientID);

        if (configData.clientSecret && configData.clientSecret.trim().length > 0) {
            authorizeRequestParams.set("client_secret", configData.clientSecret);
        }

        let scope: string = OIDC_SCOPE;

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
  
        const pkceKey: string = await this._authenticationHelper.generatePKCEKey(
            userID
        );
  
        if (configData.enablePKCE) {
            const codeVerifier: string = this._cryptoHelper?.getCodeVerifier();
            const codeChallenge: string =
          this._cryptoHelper?.getCodeChallenge(codeVerifier);
  
            await this._dataLayer.setTemporaryDataParameter(
                pkceKey,
                codeVerifier,
                userID
            );
            authorizeRequestParams.set("code_challenge_method", "S256");
            authorizeRequestParams.set("code_challenge", codeChallenge);
        }

        if (configData.prompt) {
            authorizeRequestParams.set("prompt", configData.prompt);
        }

        const customParams: AuthorizationURLParams | undefined = config;

        if (customParams) {
            for (const [ key, value ] of Object.entries(customParams)) {
                if (key != "" && value != "" && key !== STATE) {
                    authorizeRequestParams.set(key, value.toString());
                }
            }
        }

        authorizeRequestParams.set(
            STATE,
            AuthenticationUtils.generateStateParamForRequestCorrelation(
                pkceKey,
                customParams ? customParams[STATE]?.toString() : ""
            )
        );
  
        return authorizeRequestParams;
    }

    public async getAuthorizationURL(config?: AuthorizationURLParams, userID?: string): Promise<string> {
        const authorizeEndpoint: string = (await this._dataLayer.getOIDCProviderMetaDataParameter(
            AUTHORIZATION_ENDPOINT as keyof OIDCProviderMetaData
        )) as string;

        if (!authorizeEndpoint || authorizeEndpoint.trim().length === 0) {
            throw new AsgardeoAuthException(
                "JS-AUTH_CORE-GAU-NF01",
                "No authorization endpoint found.",
                "No authorization endpoint was found in the OIDC provider meta data from the well-known endpoint " +
                "or the authorization endpoint passed to the SDK is empty."
            );
        }

        const authorizeRequest: URL = new URL(authorizeEndpoint);

        const authorizeRequestParams: Map<string, string> =
      await this.getAuthorizationURLParams(config, userID);

        for (const [ key, value ] of authorizeRequestParams.entries()) {
            authorizeRequest.searchParams.append(key, value);
        }

        return authorizeRequest.toString();
    }

    public async requestAccessToken(
        authorizationCode: string,
        sessionState: string,
        state: string,
        userID?: string,
        tokenRequestConfig?: {
            params: Record<string, unknown>
        }
    ): Promise<TokenResponse> {
        const tokenEndpoint: string | undefined = (await this._oidcProviderMetaData()).token_endpoint;
        const configData: StrictAuthClientConfig = await this._config();

        if (!tokenEndpoint || tokenEndpoint.trim().length === 0) {
            throw new AsgardeoAuthException(
                "JS-AUTH_CORE-RAT1-NF01",
                "Token endpoint not found.",
                "No token endpoint was found in the OIDC provider meta data returned by the well-known endpoint " +
                "or the token endpoint passed to the SDK is empty."
            );
        }

        sessionState && (await this._dataLayer.setSessionDataParameter(
            SESSION_STATE as keyof SessionData, sessionState, userID));

        const body: URLSearchParams = new URLSearchParams();

        body.set("client_id", configData.clientID);

        if (configData.clientSecret && configData.clientSecret.trim().length > 0) {
            body.set("client_secret", configData.clientSecret);
        }

        const code: string = authorizationCode;

        body.set("code", code);

        body.set("grant_type", "authorization_code");
        body.set("redirect_uri", configData.signInRedirectURL);

        if (tokenRequestConfig?.params) {
            Object.entries(tokenRequestConfig.params).forEach(([ key, value ]: [key: string, value: unknown]) => {
                body.append(key, value as string);
            });
        }

        if (configData.enablePKCE) {
            body.set(
                "code_verifier", `${await this._dataLayer.getTemporaryDataParameter(
                    AuthenticationUtils.extractPKCEKeyFromStateParam(state),
                    userID
                )}`
            );

            await this._dataLayer.removeTemporaryDataParameter(
                AuthenticationUtils.extractPKCEKeyFromStateParam(state),
                userID
            );
        }

        let tokenResponse: Response;

        try {
            tokenResponse = await fetch(tokenEndpoint, {
                body: body,
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
        const tokenEndpoint: string | undefined = (await this._oidcProviderMetaData()).token_endpoint;
        const configData: StrictAuthClientConfig = await this._config();
        const sessionData: SessionData = await this._dataLayer.getSessionData(userID);

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
        const revokeTokenEndpoint: string | undefined = (await this._oidcProviderMetaData()).revocation_endpoint;
        const configData: StrictAuthClientConfig = await this._config();

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

        if (configData.clientSecret && configData.clientSecret.trim().length > 0) {
            body.push(`client_secret=${ configData.clientSecret }`);
        }

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
        const oidcProviderMetadata: OIDCProviderMetaData = await this._oidcProviderMetaData();
        const configData: StrictAuthClientConfig = await this._config();

        let tokenEndpoint: string | undefined;

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
            Object.entries(customGrantParams.data).map(async ([ key, value ]: [ key: string, value: any ]) => {
                const newValue: string = await this._authenticationHelper.replaceCustomGrantTemplateTags(
                    value as string,
                    userID
                );

                return `${ key }=${ newValue }`;
            })
        );

        let requestHeaders: Record<string, any> = {
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
        const sessionData: SessionData = await this._dataLayer.getSessionData(userID);
        const authenticatedUser: AuthenticatedUserInfo = this._authenticationHelper
            .getAuthenticatedUserInfo(sessionData?.id_token);

        let basicUserInfo: BasicUserInfo = {
            allowedScopes: sessionData.scope,
            sessionState: sessionData.session_state
        };

        Object.keys(authenticatedUser).forEach((key: string) => {
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
        const idToken: string = (await this._dataLayer.getSessionData(userID)).id_token;
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
        const configData: StrictAuthClientConfig = await this._config();

        if (!forceInit && (await this._dataLayer.getTemporaryDataParameter(OP_CONFIG_INITIATED))) {
            return Promise.resolve();
        }

        const wellKnownEndpoint: string = (configData as any).wellKnownEndpoint;

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
            await this._dataLayer.setOIDCProviderMetaData(
                await this._authenticationHelper.resolveEndpointsExplicitly());

            await this._dataLayer.setTemporaryDataParameter(OP_CONFIG_INITIATED, true);

            return Promise.resolve();
        }
    }

    public async getOIDCServiceEndpoints(): Promise<OIDCEndpoints> {
        const oidcProviderMetaData: OIDCProviderMetaData = await this._oidcProviderMetaData();

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
        const logoutEndpoint: string | undefined = (await this._oidcProviderMetaData())?.end_session_endpoint;
        const configData: StrictAuthClientConfig = await this._config();

        if (!logoutEndpoint || logoutEndpoint.trim().length === 0) {
            throw new AsgardeoAuthException(
                "JS-AUTH_CORE-GSOU-NF01",
                "Sign-out endpoint not found.",
                "No sign-out endpoint was found in the OIDC provider meta data returned by the well-known endpoint " +
                "or the sign-out endpoint passed to the SDK is empty."
            );
        }

        const callbackURL: string = configData?.signOutRedirectURL ?? configData?.signInRedirectURL;

        if (!callbackURL || callbackURL.trim().length === 0) {
            throw new AsgardeoAuthException(
                "JS-AUTH_CORE-GSOU-NF03",
                "No sign-out redirect URL found.",
                "The sign-out redirect URL cannot be found or the URL passed to the SDK is empty. " +
                "No sign-in redirect URL has been found either. "
            );
        }
        const queryParams: URLSearchParams = new URLSearchParams();

        queryParams.set("post_logout_redirect_uri", callbackURL);

        if (configData.sendIdTokenInLogoutRequest) {
            const idToken: string = (await this._dataLayer.getSessionData(userID))?.id_token;

            if (!idToken || idToken.trim().length === 0) {
                throw new AsgardeoAuthException(
                    "JS-AUTH_CORE-GSOU-NF02",
                    "ID token not found.",
                    "No ID token could be found. Either the session information is lost or you have not signed in."
                );
            }
            queryParams.set("id_token_hint", idToken);
        } else {
            queryParams.set("client_id", configData.clientID);
        }

        queryParams.set("state", SIGN_OUT_SUCCESS_PARAM);

        return `${logoutEndpoint}?${queryParams.toString()}`;
    }

    public async clearUserSessionData(userID?: string): Promise<void> {
        await this._authenticationHelper.clearUserSessionData(userID);
    }

    public async getAccessToken(userID?: string): Promise<string> {
        return (await this._dataLayer.getSessionData(userID))?.access_token;
    }

    /**
     * The created timestamp of the token response in milliseconds.
     * 
     * @param userID - User ID
     * @returns Created at timestamp of the token response in milliseconds.
     */
    public async getCreatedAt(userID?: string): Promise<number> {
        return (await this._dataLayer.getSessionData(userID))?.created_at;
    }

    /**
     * The expires timestamp of the token response in seconds.
     * 
     * @param userID - User ID
     * @returns Expires in timestamp of the token response in seconds.
     */
    public async getExpiresIn(userID?: string): Promise<string> {
        return (await this._dataLayer.getSessionData(userID))?.expires_in;
    }

    public async isAuthenticated(userID?: string): Promise<boolean> {
        const isAccessTokenAvailable: boolean = Boolean(await this.getAccessToken(userID));

        // Check if the access token is expired.
        const createdAt: number = await this.getCreatedAt(userID);

        // Get the expires in value.
        const expiresInString: string = await this.getExpiresIn(userID);

        // If the expires in value is not available, the token is invalid and the user is not authenticated.
        if (!expiresInString) {
            return false;
        }

        // Convert to milliseconds.
        const expiresIn: number = parseInt(expiresInString) * 1000;
        const currentTime: number = new Date().getTime();
        const isAccessTokenValid: boolean = (createdAt + expiresIn) > currentTime;

        const isAuthenticated: boolean = isAccessTokenAvailable && isAccessTokenValid;

        return isAuthenticated;
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
