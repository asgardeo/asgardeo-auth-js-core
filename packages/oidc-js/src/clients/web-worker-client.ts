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

import WorkerFile from "web-worker:../worker/client.worker.ts";
import {
    DISABLE_HTTP_HANDLER,
    ENABLE_HTTP_HANDLER,
    GET_AUTH_URL,
    GET_BASIC_USER_INFO,
    GET_DECODED_ID_TOKEN,
    GET_OIDC_SERVICE_ENDPOINTS,
    GET_SIGN_OUT_URL,
    HTTP_REQUEST,
    HTTP_REQUEST_ALL,
    INIT,
    IS_AUTHENTICATED,
    REFRESH_ACCESS_TOKEN,
    REQUEST_ACCESS_TOKEN,
    REQUEST_CUSTOM_GRANT,
    REQUEST_ERROR,
    REQUEST_FINISH,
    REQUEST_START,
    REQUEST_SUCCESS,
    REVOKE_ACCESS_TOKEN,
    SET_SESSION_STATE,
    SIGN_OUT,
    START_AUTO_REFRESH_TOKEN
} from "../constants";
import {
    AUTHORIZATION_CODE,
    AuthClientConfig,
    BasicUserInfo,
    CustomGrantConfig,
    DecodedIdTokenPayload,
    OIDCEndpoints,
    OIDCProviderMetaData,
    ResponseMode,
    SESSION_STATE,
    SignInConfig
} from "../core";
import { AsgardeoSPAException } from "../exception";
import { SessionManagementHelper } from "../helpers";
import {
    AuthorizationInfo,
    AuthorizationResponse,
    HttpClient,
    HttpError,
    HttpRequestConfig,
    HttpResponse,
    Message,
    ResponseMessage,
    WebWorkerClientConfig,
    WebWorkerClientInterface
} from "../models";
import { SPAUtils } from "../utils";

export const WebWorkerClient = (config: AuthClientConfig<WebWorkerClientConfig>): WebWorkerClientInterface => {
    /**
     * HttpClient handlers
     */
    let httpClientHandlers: HttpClient;
    /**
     * API request time out.
     */
    const _requestTimeout: number = config?.requestTimeout ?? 60000;
    const _sessionManagementHelper = SessionManagementHelper();

    const worker: Worker = new WorkerFile();

    const communicate = <T, R>(message: Message<T>): Promise<R> => {
        const channel = new MessageChannel();

        worker.postMessage(message, [channel.port2]);

        return new Promise((resolve, reject) => {
            const timer = setTimeout(() => {
                reject(
                    new AsgardeoSPAException(
                        "WEB_WORKER_CLIENT-COM-TO-01",
                        "web-worker-client",
                        "communicate",
                        "Operation timed out.",
                        "No response was received from the web worker for " +
                            _requestTimeout / 1000 +
                            " since dispatching the request"
                    )
                );
            }, _requestTimeout);

            return (channel.port1.onmessage = ({ data }: { data: ResponseMessage<string> }) => {
                clearTimeout(timer);

                if (data?.success) {
                    const responseData = JSON.parse(data?.data);
                    if (data?.blob) {
                        responseData.data = data?.blob;
                    }

                    resolve(responseData);
                } else {
                    reject(JSON.parse(data.error));
                }
            });
        });
    };

    /**
     * Allows using custom grant types.
     *
     * @param {CustomGrantRequestParams} requestParams Request Parameters.
     *
     * @returns {Promise<HttpResponse|boolean>} A promise that resolves with a boolean value or the request
     * response if the the `returnResponse` attribute in the `requestParams` object is set to `true`.
     */
    const requestCustomGrant = (requestParams: CustomGrantConfig): Promise<HttpResponse | BasicUserInfo> => {
        const message: Message<CustomGrantConfig> = {
            data: requestParams,
            type: REQUEST_CUSTOM_GRANT
        };

        return communicate<CustomGrantConfig, HttpResponse | BasicUserInfo>(message)
            .then((response) => {
                return Promise.resolve(response);
            })
            .catch((error) => {
                return Promise.reject(error);
            });
    };

    /**
     *
     * Send the API request to the web worker and returns the response.
     *
     * @param {HttpRequestConfig} config The Http Request Config object
     *
     * @returns {Promise<HttpResponse>} A promise that resolves with the response data.
     */
    const httpRequest = <T = any>(config: HttpRequestConfig): Promise<HttpResponse<T>> => {
        const message: Message<HttpRequestConfig> = {
            data: config,
            type: HTTP_REQUEST
        };

        return communicate<HttpRequestConfig, HttpResponse<T>>(message)
            .then((response) => {
                return Promise.resolve(response);
            })
            .catch((error) => {
                return Promise.reject(error);
            });
    };

    /**
     *
     * Send multiple API requests to the web worker and returns the response.
     * Similar `axios.spread` in functionality.
     *
     * @param {HttpRequestConfig[]} configs - The Http Request Config object
     *
     * @returns {Promise<HttpResponse<T>[]>} A promise that resolves with the response data.
     */
    const httpRequestAll = <T = any>(configs: HttpRequestConfig[]): Promise<HttpResponse<T>[]> => {
        const message: Message<HttpRequestConfig[]> = {
            data: configs,
            type: HTTP_REQUEST_ALL
        };

        return communicate<HttpRequestConfig[], HttpResponse<T>[]>(message)
            .then((response) => {
                return Promise.resolve(response);
            })
            .catch((error) => {
                return Promise.reject(error);
            });
    };

    const enableHttpHandler = (): Promise<boolean> => {
        const message: Message<null> = {
            type: ENABLE_HTTP_HANDLER
        };
        return communicate<null, null>(message)
            .then(() => {
                return Promise.resolve(true);
            })
            .catch((error) => {
                return Promise.reject(error);
            });
    };

    const disableHttpHandler = (): Promise<boolean> => {
        const message: Message<null> = {
            type: DISABLE_HTTP_HANDLER
        };
        return communicate<null, null>(message)
            .then(() => {
                return Promise.resolve(true);
            })
            .catch((error) => {
                return Promise.reject(error);
            });
    };

    /**
     * Initializes the object with authentication parameters.
     *
     * @param {ConfigInterface} config The configuration object.
     *
     * @returns {Promise<boolean>} Promise that resolves when initialization is successful.
     *
     */
    const initialize = (): Promise<boolean> => {
        httpClientHandlers = {
            requestErrorCallback: null,
            requestFinishCallback: null,
            requestStartCallback: null,
            requestSuccessCallback: null
        };

        worker.onmessage = ({ data }) => {
            switch (data.type) {
                case REQUEST_ERROR:
                    httpClientHandlers?.requestErrorCallback &&
                        httpClientHandlers?.requestErrorCallback(JSON.parse(data.data ?? ""));
                    break;
                case REQUEST_FINISH:
                    httpClientHandlers?.requestFinishCallback && httpClientHandlers?.requestFinishCallback();
                    break;
                case REQUEST_START:
                    httpClientHandlers?.requestStartCallback && httpClientHandlers?.requestStartCallback();
                    break;
                case REQUEST_SUCCESS:
                    httpClientHandlers?.requestSuccessCallback &&
                        httpClientHandlers?.requestSuccessCallback(JSON.parse(data.data ?? ""));
                    break;
            }
        };

        const message: Message<AuthClientConfig<WebWorkerClientConfig>> = {
            data: config,
            type: INIT
        };

        return communicate<AuthClientConfig<WebWorkerClientConfig>, null>(message)
            .then(() => {
                return Promise.resolve(true);
            })
            .catch((error) => {
                return Promise.reject(error);
            });
    };

    const setSessionState = (sessionState: string): Promise<void> => {
        const message: Message<string> = {
            data: sessionState,
            type: SET_SESSION_STATE
        };

        return communicate<string, void>(message);
    };

    const startAutoRefreshToken = (): Promise<void> => {
        const message: Message<null> = {
            type: START_AUTO_REFRESH_TOKEN
        };

        return communicate<null, void>(message);
    };

    const checkSession = async (): Promise<void> => {
        const oidcEndpoints: OIDCEndpoints = await getOIDCServiceEndpoints();
        const sessionState: string = (await getBasicUserInfo()).sessionState;

        _sessionManagementHelper.initialize(
            config.clientID,
            oidcEndpoints.checkSessionIframe,
            sessionState,
            3,
            config.signInRedirectURL,
            oidcEndpoints.authorizationEndpoint
        );

        _sessionManagementHelper.initiateCheckSession();
    };

    /**
     * Initiates the authentication flow.
     *
     * @returns {Promise<UserInfo>} A promise that resolves when authentication is successful.
     */
    const signIn = async (
        params?: SignInConfig,
        authorizationCode?: string,
        sessionState?: string
    ): Promise<BasicUserInfo> => {
        const isLoggingOut = await _sessionManagementHelper.receivePromptNoneResponse(
            async () => {
                const message: Message<string> = {
                    type: SIGN_OUT
                };

                try {
                    const signOutURL = await communicate<string, string>(message);

                    return signOutURL;
                } catch {
                    return SPAUtils.getSignOutURL();
                }
            },
            async (sessionState: string) => {
                return setSessionState(sessionState);
            }
        );

        if (isLoggingOut) {
            return Promise.resolve({
                allowedScopes: "",
                displayName: "",
                email: "",
                sessionState: "",
                tenantDomain: "",
                username: ""
            });
        }

        if (await isAuthenticated()) {
            await startAutoRefreshToken();
            checkSession();

            return getBasicUserInfo();
        }

        let resolvedAuthorizationCode: string;
        let resolvedSessionState: string;

        if (config?.responseMode === ResponseMode.formPost && (authorizationCode || sessionState)) {
            resolvedAuthorizationCode = authorizationCode;
            resolvedSessionState = sessionState;
        } else {
            resolvedAuthorizationCode = new URL(window.location.href).searchParams.get(AUTHORIZATION_CODE);
            resolvedSessionState = new URL(window.location.href).searchParams.get(SESSION_STATE);
            SPAUtils.removeAuthorizationCode();
        }

        if (resolvedAuthorizationCode && resolvedSessionState) {
            const message: Message<AuthorizationInfo> = {
                data: {
                    code: resolvedAuthorizationCode,
                    pkce: SPAUtils.getPKCE(),
                    sessionState: resolvedSessionState
                },
                type: REQUEST_ACCESS_TOKEN
            };

            SPAUtils.removePKCE();

            return communicate<AuthorizationInfo, BasicUserInfo>(message)
                .then((response) => {
                    const message: Message<null> = {
                        type: GET_SIGN_OUT_URL
                    };

                    return communicate<null, string>(message)
                        .then((url: string) => {
                            SPAUtils.setSignOutURL(url);
                            checkSession();

                            return Promise.resolve(response);
                        })
                        .catch((error) => {
                            return Promise.reject(error);
                        });
                })
                .catch((error) => {
                    return Promise.reject(error);
                });
        }

        const message: Message<SignInConfig> = {
            data: params,
            type: GET_AUTH_URL
        };

        return communicate<SignInConfig, AuthorizationResponse>(message)
            .then((response) => {
                if (response.pkce) {
                    SPAUtils.setPKCE(response.pkce);
                }

                location.href = response.authorizationURL;

                return Promise.resolve({
                    allowedScopes: "",
                    displayName: "",
                    email: "",
                    sessionState: "",
                    tenantDomain: "",
                    username: ""
                });
            })
            .catch((error) => {
                return Promise.reject(error);
            });
    };

    /**
     * Initiates the sign out flow.
     *
     * @returns {Promise<boolean>} A promise that resolves when sign out is completed.
     */
    const signOut = (): Promise<boolean> => {
        return isAuthenticated()
            .then((response: boolean) => {
                if (response) {
                    const message: Message<null> = {
                        type: SIGN_OUT
                    };

                    return communicate<string, string>(message)
                        .then((response) => {
                            window.location.href = response;

                            return Promise.resolve(true);
                        })
                        .catch((error) => {
                            return Promise.reject(error);
                        });
                } else {
                    window.location.href = SPAUtils.getSignOutURL();

                    return Promise.resolve(true);
                }
            })
            .catch((error) => {
                return Promise.reject(error);
            });
    };

    /**
     * Revokes token.
     *
     * @returns {Promise<boolean>} A promise that resolves when revoking is completed.
     */
    const revokeAccessToken = (): Promise<boolean> => {
        const message: Message<null> = {
            type: REVOKE_ACCESS_TOKEN
        };

        return communicate<null, boolean>(message)
            .then((response) => {
                return Promise.resolve(response);
            })
            .catch((error) => {
                return Promise.reject(error);
            });
    };

    const getOIDCServiceEndpoints = (): Promise<OIDCProviderMetaData> => {
        const message: Message<null> = {
            type: GET_OIDC_SERVICE_ENDPOINTS
        };

        return communicate<null, OIDCProviderMetaData>(message)
            .then((response) => {
                return Promise.resolve(response);
            })
            .catch((error) => {
                return Promise.reject(error);
            });
    };

    const getBasicUserInfo = (): Promise<BasicUserInfo> => {
        const message: Message<null> = {
            type: GET_BASIC_USER_INFO
        };

        return communicate<null, BasicUserInfo>(message)
            .then((response) => {
                return Promise.resolve(response);
            })
            .catch((error) => {
                return Promise.reject(error);
            });
    };

    const getDecodedIDToken = (): Promise<DecodedIdTokenPayload> => {
        const message: Message<null> = {
            type: GET_DECODED_ID_TOKEN
        };

        return communicate<null, DecodedIdTokenPayload>(message)
            .then((response) => {
                return Promise.resolve(response);
            })
            .catch((error) => {
                return Promise.reject(error);
            });
    };

    const isAuthenticated = (): Promise<boolean> => {
        const message: Message<null> = {
            type: IS_AUTHENTICATED
        };

        return communicate<null, boolean>(message)
            .then((response) => {
                return Promise.resolve(response);
            })
            .catch((error) => {
                return Promise.reject(error);
            });
    };

    const refreshAccessToken = (): Promise<BasicUserInfo> => {
        const message: Message<null> = {
            type: REFRESH_ACCESS_TOKEN
        };

        return communicate<null, BasicUserInfo>(message);
    };

    const setHttpRequestSuccessCallback = (callback: (response: HttpResponse) => void): void => {
        if (callback && typeof callback === "function") {
            httpClientHandlers.requestSuccessCallback = callback;
        }
    };

    const setHttpRequestErrorCallback = (callback: (response: HttpError) => void): void => {
        if (callback && typeof callback === "function") {
            httpClientHandlers.requestErrorCallback = callback;
        }
    };

    const setHttpRequestStartCallback = (callback: () => void): void => {
        if (callback && typeof callback === "function") {
            httpClientHandlers.requestStartCallback = callback;
        }
    };

    const setHttpRequestFinishCallback = (callback: () => void): void => {
        if (callback && typeof callback === "function") {
            httpClientHandlers.requestFinishCallback = callback;
        }
    };

    return {
        disableHttpHandler,
        enableHttpHandler,
        getBasicUserInfo,
        getDecodedIDToken,
        getOIDCServiceEndpoints,
        httpRequest,
        httpRequestAll,
        initialize,
        isAuthenticated,
        refreshAccessToken,
        requestCustomGrant,
        revokeAccessToken,
        setHttpRequestErrorCallback,
        setHttpRequestFinishCallback,
        setHttpRequestStartCallback,
        setHttpRequestSuccessCallback,
        signIn,
        signOut
    };
};
