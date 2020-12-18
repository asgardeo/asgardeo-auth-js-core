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
    API_CALL,
    API_CALL_ALL,
    AUTH_REQUIRED,
    CUSTOM_GRANT,
    DISABLE_HTTP_HANDLER,
    ENABLE_HTTP_HANDLER,
    END_USER_SESSION,
    GET_DECODED_ID_TOKEN,
    GET_SERVICE_ENDPOINTS,
    GET_USER_INFO,
    INIT,
    LOGOUT,
    REQUEST_ERROR,
    REQUEST_FINISH,
    REQUEST_START,
    REQUEST_SUCCESS,
    SIGNED_IN,
    SIGN_IN,
    GET_TOKEN,
    GET_AUTH_URL,
    IS_AUTHENTICATED,
    GET_SIGN_OUT_URL
} from "../constants";
import {
    AuthCode,
    HttpClient,
    HttpError,
    HttpRequestConfig,
    HttpResponse,
    Message,
    ResponseMessage,
    SignInResponse,
    SignInResponseWorker,
    WebWorkerClientInterface,
    WebWorkerConfigInterface,
    WebWorkerSingletonClientInterface,
    ConfigInterface,
    GetAuthorizationURLInterface
} from "../models";
import { getAuthorizationCode } from "../utils";
import { AuthenticationUtils } from "../core/utils/authentication-utils";
import WorkerFile from "web-worker:../worker/oidc.worker.ts";
import { SPAUtils } from "../utils/spa-utils";
import { CustomGrantConfig, ResponseMode, AUTHORIZATION_CODE, SESSION_STATE, SignInConfig, BasicUserInfo, OIDCProviderMetaData, DecodedIdTokenPayload } from "../core";

export const WebWorkerClient = (config: WebWorkerConfigInterface): WebWorkerClientInterface => {
    /**
     * The private boolean member variable that specifies if the `initialize()` method has been called or not.
     */
    let initialized: boolean = false;
    /**
     * The private boolean member variable that specifies if the user is signed in or not.
     */
    let signedIn: boolean = false;
    /**
     * HttpClient handlers
     */
    let httpClientHandlers: HttpClient;
    /**
     * API request time out.
     */
    const _requestTimeout: number = config?.requestTimeout ?? 60000;

    const worker: Worker = new WorkerFile();

    const communicate = <T, R>(message: Message<T>): Promise<R> => {
        const channel = new MessageChannel();

        worker.postMessage(message, [channel.port2]);

        return new Promise((resolve, reject) => {
            const timer = setTimeout(() => {
                reject("Operation timed out");
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
    const customGrant = (
        requestParams: CustomGrantConfig
    ): Promise<HttpResponse |SignInResponse> => {
        if (!initialized) {
            return Promise.reject("The object has not been initialized yet");
        }

        if (!signedIn && requestParams.signInRequired) {
            return Promise.reject("You have not signed in yet");
        }

        const message: Message<CustomGrantConfig> = {
            data: requestParams,
            type: CUSTOM_GRANT
        };

        return communicate<
            CustomGrantConfig,
            HttpResponse | SignInResponse
        >(message)
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
        if (!initialized) {
            return Promise.reject("The object has not been initialized yet");
        }

        if (!signedIn) {
            return Promise.reject("You have not signed in yet");
        }

        const message: Message<HttpRequestConfig> = {
            data: config,
            type: API_CALL
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
        if (!initialized) {
            return Promise.reject("The object has not been initialized yet");
        }

       /*  if (!signedIn) {
            return Promise.reject("You have not signed in yet");
        } */

        const message: Message<HttpRequestConfig[]> = {
            data: configs,
            type: API_CALL_ALL
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
            if (config.authorizationType && typeof config.authorizationType !== "string") {
                return Promise.reject("The authorizationType must be a string");
            }

            if (!(config.resourceServerURLs instanceof Array)) {
                return Promise.reject("resourceServerURLs must be an array");
            }

            if (config.resourceServerURLs.find((baseUrl) => typeof baseUrl !== "string")) {
                return Promise.reject("Array elements of resourceServerURLs must all be string values");
            }

            if (typeof config.signInRedirectURL !== "string") {
                return Promise.reject("The sign-in redirect URL must be a string");
            }

            if (typeof config.signOutRedirectURL !== "string") {
                return Promise.reject("The sign-out redirect URL must be a string");
            }

            if (typeof config.clientHost !== "string") {
                return Promise.reject("The clientHost must be a string");
            }

            if (typeof config.clientID !== "string") {
                return Promise.reject("The clientID must be a string");
            }

            if (config.clientSecret && typeof config.clientSecret !== "string") {
                return Promise.reject("The clientString must be a string");
            }

            if (config.consentDenied && typeof config.consentDenied !== "boolean") {
                return Promise.reject("consentDenied must be a boolean");
            }

            if (config.enablePKCE && typeof config.enablePKCE !== "boolean") {
                return Promise.reject("enablePKCE must be a boolean");
            }

            if (config.prompt && typeof config.prompt !== "string") {
                return Promise.reject("The prompt must be a string");
            }

            if (config.responseMode && typeof config.responseMode !== "string") {
                return Promise.reject("The responseMode must be a string");
            }

            if (config.responseMode
                && config.responseMode !== ResponseMode.formPost
                && config.responseMode !== ResponseMode.query) {
                return Promise.reject("The responseMode is invalid");
            }

            if (config.scope && !(config.scope instanceof Array)) {
                return Promise.reject("scope must be an array");
            }

            if (config.scope && config.scope.find((aScope) => typeof aScope !== "string")) {
                return Promise.reject("Array elements of scope must all be string values");
            }

            if (typeof config.serverOrigin !== "string") {
                return Promise.reject("serverOrigin must be a string");
            }


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


        const message: Message<WebWorkerConfigInterface> = {
            data: config,
            type: INIT
        };

        return communicate<WebWorkerConfigInterface, null>(message)
            .then(() => {
                initialized = true;

                return Promise.resolve(true);
            })
            .catch((error) => {
                return Promise.reject(error);
            });
    };

    /**
     * Initiates the authentication flow.
     *
     * @returns {Promise<UserInfo>} A promise that resolves when authentication is successful.
     */
    const signIn = (
        params?: SignInConfig,
        authorizationCode?: string,
        sessionState?: string
    ): Promise<BasicUserInfo> => {
        let resolvedAuthorizationCode: string;
        let resolvedSessionState: string;

        if (config?.responseMode === ResponseMode.formPost && (authorizationCode || sessionState)) {
            resolvedAuthorizationCode = authorizationCode;
            resolvedSessionState = sessionState;
        } else {
            resolvedAuthorizationCode = new URL(window.location.href).searchParams.get(AUTHORIZATION_CODE);
            resolvedSessionState = new URL(window.location.href).searchParams.get(SESSION_STATE);
        }

        if (resolvedAuthorizationCode && resolvedSessionState) {
            const message: Message<AuthCode> = {
                data: {
                    code: resolvedAuthorizationCode,
                    pkce: SPAUtils.getPKCE(),
                    sessionState: resolvedSessionState
                },
                type: GET_TOKEN
            };

            SPAUtils.removeAuthorizationCode();

            SPAUtils.removePKCE();

            return communicate<AuthCode, BasicUserInfo>(message)
                .then((response) => {
                    signedIn = true;

                    const message: Message<null> = {
                        type: GET_SIGN_OUT_URL
                    };

                    return communicate<null, string>(message)
                        .then((url: string) => {
                            SPAUtils.setSignOutURL(url);
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

        return communicate<SignInConfig, GetAuthorizationURLInterface>(message)
            .then((response) => {
                if (response.pkce) {
                    SPAUtils.setPKCE(response.pkce);
                }

                location.href = response.authorizationCode;

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
        return isAuthenticated().then((response: boolean) => {
            console.log("authenticated");
            if (response) {
                const message: Message<null> = {
                    type: LOGOUT
                };

                return communicate<null, string>(message)
                    .then((response) => {
                        signedIn = false;
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
        }).catch((error) => {
            return Promise.reject(error);
        })
    };

    /**
     * Revokes token.
     *
     * @returns {Promise<boolean>} A promise that resolves when revoking is completed.
     */
    const endUserSession = (): Promise<boolean> => {
        if (!signedIn) {
            return Promise.reject("You have not signed in yet");
        }

        const message: Message<null> = {
            type: END_USER_SESSION
        };

        return communicate<null, boolean>(message)
            .then((response) => {
                return Promise.resolve(response);
            })
            .catch((error) => {
                return Promise.reject(error);
            });
    };

    const getServiceEndpoints = (): Promise<OIDCProviderMetaData> => {
        const message: Message<null> = {
            type: GET_SERVICE_ENDPOINTS
        };

        return communicate<null, OIDCProviderMetaData>(message)
            .then((response) => {
                return Promise.resolve(response);
            })
            .catch((error) => {
                return Promise.reject(error);
            });
    };

    const getUserInfo = (): Promise<BasicUserInfo> => {
        const message: Message<null> = {
            type: GET_USER_INFO
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

        return communicate<null, boolean>(message).then((response) => {
            return Promise.resolve(response);
        }).catch((error) => {
            return Promise.reject(error);
        });
    }

    const onHttpRequestSuccess = (callback: (response: HttpResponse) => void): void => {
        if (callback && typeof callback === "function") {
            httpClientHandlers.requestSuccessCallback = callback;
        }
    };

    const onHttpRequestError = (callback: (response: HttpError) => void): void => {
        if (callback && typeof callback === "function") {
            httpClientHandlers.requestErrorCallback = callback;
        }
    };

    const onHttpRequestStart = (callback: () => void): void => {
        if (callback && typeof callback === "function") {
            httpClientHandlers.requestStartCallback = callback;
        }
    };

    const onHttpRequestFinish = (callback: () => void): void => {
        if (callback && typeof callback === "function") {
            httpClientHandlers.requestFinishCallback = callback;
        }
    };


        return {
            customGrant,
            disableHttpHandler,
            enableHttpHandler,
            endUserSession,
            getDecodedIDToken,
            getServiceEndpoints,
            getUserInfo,
            httpRequest,
            httpRequestAll,
            initialize,
            onHttpRequestError,
            onHttpRequestFinish,
            onHttpRequestStart,
            onHttpRequestSuccess,
            signIn,
            signOut,
            //isAuthenticated
        };

};
