/**
 * Copyright (c) 2019, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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

import axios from "axios";
import { getSessionParameter, removeSessionParameter, setSessionParameter } from "./session-storage";
import {
    AUTHORIZATION_ENDPOINT,
    CLIENT_ID,
    END_SESSION_ENDPOINT,
    INTROSPECTION_ENDPOINT,
    ISSUER,
    JWKS_ENDPOINT,
    OIDC_SESSION_IFRAME_ENDPOINT,
    OPEN_ID_CONFIG,
    OP_CONFIG_INITIATED,
    REGISTRATION_ENDPOINT,
    REVOKE_TOKEN_ENDPOINT,
    SERVICE_RESOURCES,
    SIGN_IN_REDIRECT_URL,
    SIGN_OUT_REDIRECT_URL,
    Storage,
    TENANT,
    TOKEN_ENDPOINT,
    USERINFO_ENDPOINT,
    USERNAME
} from "../constants";
import {
    ConfigInterface,
    OIDCEndpointConstantsInterface,
    OIDCProviderMetaData,
    OpenIDConfig,
    WebWorkerConfigInterface
} from "../models";

/**
 * Checks whether openid configuration initiated.
 *
 * @returns {boolean}
 */
export const isOPConfigInitiated = (requestParams: ConfigInterface): boolean => {
    if (requestParams.storage !== Storage.WebWorker) {
        return (
            getSessionParameter(OP_CONFIG_INITIATED, requestParams) &&
            getSessionParameter(OP_CONFIG_INITIATED, requestParams) === "true"
        );
    } else {
        return (
            requestParams.session.get(OP_CONFIG_INITIATED) && requestParams.session.get(OP_CONFIG_INITIATED) === "true"
        );
    }
};

/**
 * Set OAuth2 authorize endpoint.
 *
 * @param {string} authorizationEndpoint
 */
export const setAuthorizeEndpoint = (
    authorizationEndpoint: string,
    requestParams: ConfigInterface
): void => {
    setSessionParameter(AUTHORIZATION_ENDPOINT, authorizationEndpoint, requestParams);
};

/**
 * Sets the open id config data on the session.
 *
 * @param {OpenIDConfig} data - The Open ID Config.
 * @param {ConfigInterface} requestParams - Initial Config.
 */
export const setOPConfig = (data: OpenIDConfig, requestParams: ConfigInterface): void => {
    setSessionParameter(OPEN_ID_CONFIG, JSON.stringify(data), requestParams)
}

/**
 * Returns the Open ID config from the session.
 *
 * @param {ConfigInterface} requestParams - Initial Config.
 *
 * @return {OpenIDConfig} - Open ID Config.
 */
export const getOPConfig = (requestParams: ConfigInterface): OpenIDConfig => {
    return JSON.parse(getSessionParameter(OPEN_ID_CONFIG, requestParams));
}

/**
 * Set OAuth2 token endpoint.
 *
 * @param {string} tokenEndpoint
 */
export const setTokenEndpoint = (
    tokenEndpoint: string, requestParams: ConfigInterface): void => {
    setSessionParameter(TOKEN_ENDPOINT, tokenEndpoint, requestParams);
};

/**
 * Set OIDC end session endpoint.
 *
 * @param {string} endSessionEndpoint
 */
export const setEndSessionEndpoint = (
    endSessionEndpoint: string,
    requestParams: ConfigInterface
): void => {
    setSessionParameter(END_SESSION_ENDPOINT, endSessionEndpoint, requestParams);
};

/**
 * Set JWKS URI.
 *
 * @param jwksEndpoint
 */
export const setJwksUri = (jwksEndpoint: string, requestParams: ConfigInterface): void => {
    setSessionParameter(JWKS_ENDPOINT, jwksEndpoint, requestParams);
};

/**
 * Set OAuth2 revoke token endpoint.
 *
 * @param {string} revokeTokenEndpoint
 */
export const setRevokeTokenEndpoint = (
    revokeTokenEndpoint: string,
    requestParams: ConfigInterface
): void => {
    setSessionParameter(REVOKE_TOKEN_ENDPOINT, revokeTokenEndpoint, requestParams);
};

/**
 * Set openid configuration initiated.
 */
export const setOPConfigInitiated = (requestParams: ConfigInterface): void => {
    setSessionParameter(OP_CONFIG_INITIATED, "true", requestParams);
};

/**
 * Set sign-in redirect URL.
 */
export const setSignInRedirectURL = (url: string, requestParams: ConfigInterface): void => {
    setSessionParameter(SIGN_IN_REDIRECT_URL, url, requestParams);
};

/**
 * Set sign-out redirect URL.
 */
export const setSignOutRedirectURL = (url: string, requestParams: ConfigInterface): void => {
    setSessionParameter(SIGN_OUT_REDIRECT_URL, url, requestParams);
};

/**
 * Set OIDC Session IFrame URL.
 */
export const setOIDCSessionIFrameURL = (
    url: string,
    requestParams: ConfigInterface
): void => {
    setSessionParameter(OIDC_SESSION_IFRAME_ENDPOINT, url, requestParams);
};

/**
 * Set id_token issuer.
 *
 * @param issuer id_token issuer.
 */
export const setIssuer = (issuer: string, requestParams: ConfigInterface): void => {
    setSessionParameter(ISSUER, issuer, requestParams);
};

/**
 * Set Client ID.
 *
 * @param {string} clientID - Client ID of the application.
 */
export const setClientID = (requestParams: ConfigInterface): void => {
    setSessionParameter(CLIENT_ID, requestParams.clientID, requestParams);
};

const resolveEndpoint = (
    config: ConfigInterface | WebWorkerConfigInterface,
    endpointName: string,
    response: OIDCProviderMetaData
): string => {
    const camelCasedName = endpointName.split("_").map((name: string, index: number) => {

        if (index !== 0) {
            return name[ 0 ].toUpperCase() + name.substring(1);
        }

        return name;
    }).join("");

    if (config.overrideWellEndpointConfig && config.endpoints[camelCasedName]) {
        return config.serverOrigin + config.endpoints[camelCasedName];
    }

    return response[endpointName];
}

export const resolveWellKnownEndpoint = (config: ConfigInterface | WebWorkerConfigInterface): string => {
    if (config.wellKnownEndpoint) {
        return config.serverOrigin + config.wellKnownEndpoint;
    }

    return config.serverOrigin + SERVICE_RESOURCES.wellKnownEndpoint;
}

/**
 * Initialize openid provider configuration.
 *
 * @param {string} wellKnownEndpoint openid provider configuration.
 * @param {boolean} forceInit whether to initialize the configuration again.
 * @returns {Promise<any>} promise.
 */
/* eslint-disable @typescript-eslint/no-explicit-any */
export const initOPConfiguration = (
    requestParams: ConfigInterface,
    forceInit: boolean
): Promise<any> => {
    if (!forceInit && isValidOPConfig(requestParams)) {
        return Promise.resolve();
    }

    const serverHost = requestParams.serverOrigin;
    const wellKnownEndpoint = resolveWellKnownEndpoint(requestParams);

    return axios
        .get(wellKnownEndpoint)
        .then((response: { data: OpenIDConfig; status: number; }) => {
            if (response.status !== 200) {
                return Promise.reject(
                    new Error(
                        "Failed to load OpenID provider configuration from: "
                        + serverHost + SERVICE_RESOURCES.wellKnownEndpoint
                    )
                );
            }

            setOPConfig(response.data, requestParams);
            setAuthorizeEndpoint(
                resolveEndpoint(requestParams, AUTHORIZATION_ENDPOINT, response.data), requestParams
            );
            setTokenEndpoint(resolveEndpoint(requestParams, TOKEN_ENDPOINT, response.data), requestParams);
            setEndSessionEndpoint(resolveEndpoint(requestParams, END_SESSION_ENDPOINT, response.data), requestParams);
            setJwksUri(resolveEndpoint(requestParams, JWKS_ENDPOINT, response.data), requestParams);
            setRevokeTokenEndpoint(
                 resolveEndpoint(requestParams, REVOKE_TOKEN_ENDPOINT, response.data),
                requestParams
            );
            setIssuer(resolveEndpoint(requestParams, ISSUER, response.data), requestParams);
            setClientID(requestParams);
            setOIDCSessionIFrameURL(
                resolveEndpoint(requestParams, OIDC_SESSION_IFRAME_ENDPOINT, response.data), requestParams);
            setSignInRedirectURL(requestParams.signInRedirectURL, requestParams);
            setSignOutRedirectURL(requestParams.signOutRedirectURL, requestParams);
            setOPConfigInitiated(requestParams);

            setSessionParameter(
                INTROSPECTION_ENDPOINT,
                resolveEndpoint(requestParams, INTROSPECTION_ENDPOINT, response.data),
                requestParams
            );

            setSessionParameter(
                REGISTRATION_ENDPOINT,
                resolveEndpoint(requestParams, REGISTRATION_ENDPOINT, response.data),
                requestParams
            );

            setSessionParameter(
                USERINFO_ENDPOINT,
                resolveEndpoint(requestParams, USERINFO_ENDPOINT, response.data),
                requestParams
            );

            return Promise.resolve(
                "Initialized OpenID Provider configuration from: " + serverHost + SERVICE_RESOURCES.wellKnownEndpoint
            );
        })
        .catch(() => {
            setAuthorizeEndpoint(
                requestParams.serverOrigin + (requestParams?.endpoints?.authorizationEndpoint
                    || SERVICE_RESOURCES.authorizationEndpoint),
                requestParams
            );
            setTokenEndpoint(
                requestParams.serverOrigin + (requestParams?.endpoints?.tokenEndpoint
                    || SERVICE_RESOURCES.tokenEndpoint),
                requestParams
            );
            setRevokeTokenEndpoint(
                requestParams.serverOrigin + (requestParams?.endpoints?.revocationEndpoint
                    || SERVICE_RESOURCES.revocationEndpoint),
                requestParams
            );
            setEndSessionEndpoint(
                requestParams.serverOrigin + (requestParams?.endpoints?.endSessionEndpoint
                    || SERVICE_RESOURCES.endSessionEndpoint),
                requestParams
            );
            setJwksUri(serverHost + (requestParams?.endpoints?.jwksUri || SERVICE_RESOURCES.jwksUri), requestParams);
            setIssuer(
                requestParams.serverOrigin + (requestParams?.endpoints?.issuer || SERVICE_RESOURCES.tokenEndpoint),
                requestParams
            );
            setClientID(requestParams);
            setOIDCSessionIFrameURL(
                requestParams.serverOrigin +
                (requestParams?.endpoints?.checkSessionIframe
                    || SERVICE_RESOURCES.checkSessionIframe),
                requestParams
            );
            setSignInRedirectURL(requestParams.signInRedirectURL, requestParams);
            setSignOutRedirectURL(requestParams.signOutRedirectURL, requestParams);
            setOPConfigInitiated(requestParams);

            return Promise.resolve(
                new Error(
                    "Initialized OpenID Provider configuration from default configuration." +
                        "Because failed to access wellknown endpoint: " +
                        serverHost +
                        SERVICE_RESOURCES.wellKnownEndpoint
                )
            );
        });
};

/**
 * Reset openid provider configuration.
 */
export const resetOPConfiguration = (requestParams: ConfigInterface): void => {
    if (requestParams.storage !== Storage.WebWorker) {
        removeSessionParameter(AUTHORIZATION_ENDPOINT, requestParams);
        removeSessionParameter(TOKEN_ENDPOINT, requestParams);
        removeSessionParameter(END_SESSION_ENDPOINT, requestParams);
        removeSessionParameter(JWKS_ENDPOINT, requestParams);
        removeSessionParameter(REVOKE_TOKEN_ENDPOINT, requestParams);
        removeSessionParameter(OP_CONFIG_INITIATED, requestParams);
        removeSessionParameter(ISSUER, requestParams);
        removeSessionParameter(CLIENT_ID, requestParams);
        removeSessionParameter(TENANT, requestParams);
        removeSessionParameter(SIGN_IN_REDIRECT_URL, requestParams);
        removeSessionParameter(SIGN_OUT_REDIRECT_URL, requestParams);
        removeSessionParameter(OIDC_SESSION_IFRAME_ENDPOINT, requestParams);
    } else {
        requestParams.session.clear();
    }
};

export const getServiceEndpoints =
    (authConfig: ConfigInterface): OIDCEndpointConstantsInterface => {
    return {
        authorizationEndpoint: getAuthorizeEndpoint(authConfig),
        checkSessionIframe: getOIDCSessionIFrameURL(authConfig),
        endSessionEndpoint: getEndSessionEndpoint(authConfig),
        introspectionEndpoint: getSessionParameter(INTROSPECTION_ENDPOINT, authConfig),
        issuer: getSessionParameter(ISSUER, authConfig),
        jwksUri: getJwksUri(authConfig),
        registrationEndpoint: getSessionParameter(REGISTRATION_ENDPOINT, authConfig),
        revocationEndpoint: getRevokeTokenEndpoint(authConfig),
        tokenEndpoint: getTokenEndpoint(authConfig),
        userinfoEndpoint: getSessionParameter(USERINFO_ENDPOINT, authConfig),
        wellKnownEndpoint: authConfig.serverOrigin + SERVICE_RESOURCES.wellKnownEndpoint
    };
};

/**
 * Get OAuth2 authorize endpoint.
 *
 * @returns {string|null}
 */
export const getAuthorizeEndpoint = (requestParams: ConfigInterface): string | null => {
    return getSessionParameter(AUTHORIZATION_ENDPOINT, requestParams);
};

/**
 * Get OAuth2 token endpoint.
 *
 * @returns {string|null}
 */
export const getTokenEndpoint = (requestParams: ConfigInterface): string | null => {
    return getSessionParameter(TOKEN_ENDPOINT, requestParams);
};

/**
 * Get OAuth2 revoke token endpoint.
 *
 * @returns {string|null}
 */
export const getRevokeTokenEndpoint = (requestParams: ConfigInterface): string | null => {
    return getSessionParameter(REVOKE_TOKEN_ENDPOINT, requestParams);
};

export const getOIDCSessionIFrameURL = (requestParams: ConfigInterface): string | null => {
    return getSessionParameter(OIDC_SESSION_IFRAME_ENDPOINT, requestParams);
};

/**
 * Get OIDC end session endpoint.
 *
 * @returns {string|null}
 */
export const getEndSessionEndpoint = (requestParams: ConfigInterface): string | null => {
    return getSessionParameter(END_SESSION_ENDPOINT, requestParams);
};

/**
 * Get JWKS URI.
 *
 * @returns {string|null}
 */
export const getJwksUri = (requestParams: ConfigInterface): string | null => {
    return getSessionParameter(JWKS_ENDPOINT, requestParams);
};

/**
 * Get authenticated user's username
 *
 * @returns {string|null}
 */
export const getUsername = (requestParams: ConfigInterface): string | null => {
    return getSessionParameter(USERNAME, requestParams);
};

/**
 * Get tenant name
 *
 * @returns {any}
 */
export const getTenant = (requestParams: ConfigInterface): string | null => {
    return getSessionParameter(TENANT, requestParams);
};

/**
 * Get id_token issuer.
 *
 * @returns {any}
 */
export const getIssuer = (requestParams: ConfigInterface): string => {
    return getSessionParameter(ISSUER, requestParams);
};

/**
 * Get Client ID.
 *
 * @return {string}
 */
export const getClientID = (requestParams: ConfigInterface): string => {
    return getSessionParameter(CLIENT_ID, requestParams);
};

/**
 * Checks whether openid configuration initiated is valid.
 *
 * @param {string} tenant - Tenant of the logged in user.
 * @param {string} clientID - Client ID of the application.
 * @return {boolean}
 */
export const isValidOPConfig = (requestParams: ConfigInterface): boolean => {
    return (
        isOPConfigInitiated(requestParams) &&
        !!getClientID(requestParams) &&
        getClientID(requestParams) === requestParams.clientID
    );
};
