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
    HTTP_REQUEST,
    HTTP_REQUEST_ALL,
    AUTH_REQUIRED,
    REQUEST_CUSTOM_GRANT,
    DISABLE_HTTP_HANDLER,
    ENABLE_HTTP_HANDLER,
    END_USER_SESSION,
    GET_DECODED_ID_TOKEN,
    GET_OIDC_SERVICE_ENDPOINTS,
    GET_BASIC_USER_INFO,
    INIT,
    SIGN_OUT,
    REQUEST_ERROR,
    REQUEST_FINISH,
    REQUEST_START,
    REQUEST_SUCCESS,
    SIGNED_IN,
    SIGN_IN,
    GET_AUTH_URL,
    REQUEST_ACCESS_TOKEN,
    IS_AUTHENTICATED,
    GET_SIGN_OUT_URL,
    REFRESH_ACCESS_TOKEN
} from "../constants";
import {
    HttpError,
    HttpResponse,
    GetAuthorizationURLInterface,
    WebWorkerClientConfig,
    WebWorkerClientInterface,
    WebWorkerCoreInterface
} from "../models";
import { WebWorkerCore } from "./worker-core";
import { BasicUserInfo, AuthClientConfig } from "../core";
import { MessageUtils } from "../utils";
import { WebWorkerClass } from "../models";

const ctx: WebWorkerClass<any> = self as any;

let webWorker: WebWorkerCoreInterface;

ctx.onmessage = ({ data, ports }) => {
    const port = ports[0];

    switch (data.type) {
        case INIT:
            try {
                const config: AuthClientConfig<WebWorkerClientConfig> = { ...data.data };
                webWorker = WebWorkerCore(config);
                webWorker.setHttpRequestError(onRequestErrorCallback);
                webWorker.setHttpRequestFinish(onRequestFinishCallback);
                webWorker.setHttpRequestStartCallback(onRequestStartCallback);
                webWorker.setHttpRequestSuccessCallback(onRequestSuccessCallback);
                port.postMessage(MessageUtils.generateSuccessMessage());
            } catch (error) {
                port.postMessage(MessageUtils.generateFailureMessage(error));
            }

            break;
        case GET_AUTH_URL:
            if (!webWorker) {
                port.postMessage(MessageUtils.generateFailureMessage("Worker has not been initiated."));
            } else {
                webWorker
                    .getAuthorizationURL(data?.data?.params, data?.data?.signInRedirectURL)
                    .then((response: GetAuthorizationURLInterface) => {
                        port.postMessage(MessageUtils.generateSuccessMessage(response));
                    })
                    .catch((error) => {
                        port.postMessage(MessageUtils.generateFailureMessage(error));
                    });
            }

            break;
        case REQUEST_ACCESS_TOKEN:
            if (!webWorker) {
                port.postMessage(MessageUtils.generateFailureMessage("Worker has not been initiated."));
            } else {
                webWorker
                    .sendTokenRequest(data?.data?.code, data?.data?.sessionState, data?.data?.pkce)
                    .then((response: BasicUserInfo) => {
                        port.postMessage(MessageUtils.generateSuccessMessage(response));
                    })
                    .catch((error) => {
                        port.postMessage(MessageUtils.generateFailureMessage(error));
                    });
            }

            break;
        case HTTP_REQUEST:
            if (!webWorker) {
                port.postMessage(MessageUtils.generateFailureMessage("Worker has not been initiated."));

                break;
            }

            if (!webWorker.isAuthenticated()) {
                port.postMessage(MessageUtils.generateFailureMessage("You have not signed in yet."));
            } else {
                webWorker
                    .httpRequest(data.data)
                    .then((response) => {
                        port.postMessage(MessageUtils.generateSuccessMessage(response));
                    })
                    .catch((error) => {
                        port.postMessage(MessageUtils.generateFailureMessage(error));
                    });
            }

            break;
        case HTTP_REQUEST_ALL:
            if (!webWorker) {
                port.postMessage(MessageUtils.generateFailureMessage("Worker has not been initiated."));

                break;
            }

            if (!webWorker.isAuthenticated()) {
                port.postMessage(MessageUtils.generateFailureMessage("You have not signed in yet."));
            } else {
                webWorker
                    .httpRequestAll(data.data)
                    .then((response) => {
                        port.postMessage(MessageUtils.generateSuccessMessage(response));
                    })
                    .catch((error) => {
                        port.postMessage(MessageUtils.generateFailureMessage(error));
                    });
            }

            break;
        case SIGN_OUT:
            console.log("logout msg received");
            if (!webWorker) {
                port.postMessage(MessageUtils.generateFailureMessage("Worker has not been initiated."));

                break;
            }

            if (!webWorker.isAuthenticated()) {
                port.postMessage(MessageUtils.generateFailureMessage("You have not signed in yet."));
            } else {
                try {
                    port.postMessage(MessageUtils.generateSuccessMessage(webWorker.signOut(data?.data)));
                } catch (error) {
                    console.log("logout msg error", error);
                    port.postMessage(MessageUtils.generateFailureMessage(error));
                }
            }

            break;
        case REQUEST_CUSTOM_GRANT:
            if (!webWorker) {
                port.postMessage(MessageUtils.generateFailureMessage("Worker has not been initiated."));

                break;
            }

            if (!webWorker.isAuthenticated() && data.data.signInRequired) {
                port.postMessage(MessageUtils.generateFailureMessage("You have not signed in yet."));

                break;
            }

            webWorker
                .customGrant(data.data)
                .then((response) => {
                    port.postMessage(MessageUtils.generateSuccessMessage(response));
                })
                .catch((error) => {
                    port.postMessage(MessageUtils.generateFailureMessage(error));
                });

            break;
        case END_USER_SESSION:
            if (!webWorker) {
                port.postMessage(MessageUtils.generateFailureMessage("Worker has not been initiated."));

                break;
            }

            if (!webWorker.isAuthenticated() && data.data.signInRequired) {
                port.postMessage(MessageUtils.generateFailureMessage("You have not signed in yet."));

                break;
            }

            webWorker
                .revokeToken()
                .then((response) => {
                    port.postMessage(MessageUtils.generateSuccessMessage(response));
                })
                .catch((error) => {
                    port.postMessage(MessageUtils.generateFailureMessage(error));
                });
            break;
        case GET_OIDC_SERVICE_ENDPOINTS:
            if (!webWorker) {
                port.postMessage(MessageUtils.generateFailureMessage("Worker has not been initiated."));

                break;
            }

            try {
                port.postMessage(MessageUtils.generateSuccessMessage(webWorker.getOIDCServiceEndpoints()));
            } catch (error) {
                port.postMessage(MessageUtils.generateFailureMessage(error));
            }

            break;
        case GET_BASIC_USER_INFO:
            if (!webWorker) {
                port.postMessage(MessageUtils.generateFailureMessage("Worker has not been initiated."));

                break;
            }

            if (!webWorker.isAuthenticated() && data.data.signInRequired) {
                port.postMessage(MessageUtils.generateFailureMessage("You have not signed in yet."));

                break;
            }

            try {
                port.postMessage(MessageUtils.generateSuccessMessage(webWorker.getUserInfo()));
            } catch (error) {
                port.postMessage(MessageUtils.generateFailureMessage(error));
            }

            break;
        case GET_DECODED_ID_TOKEN:
            if (!webWorker) {
                port.postMessage(MessageUtils.generateFailureMessage("Worker has not been initiated."));

                break;
            }

            if (!webWorker.isAuthenticated() && data.data.signInRequired) {
                port.postMessage(MessageUtils.generateFailureMessage("You have not signed in yet."));

                break;
            }

            try {
                port.postMessage(MessageUtils.generateSuccessMessage(webWorker.getDecodedIDToken()));
            } catch (error) {
                port.postMessage(MessageUtils.generateFailureMessage(error));
            }

            break;
        case ENABLE_HTTP_HANDLER:
            if (!webWorker) {
                port.postMessage(MessageUtils.generateFailureMessage("Worker has not been initiated."));

                break;
            }

            webWorker.enableHttpHandler();
            port.postMessage(MessageUtils.generateSuccessMessage());

            break;
        case DISABLE_HTTP_HANDLER:
            if (!webWorker) {
                port.postMessage(MessageUtils.generateFailureMessage("Worker has not been initiated."));

                break;
            }

            webWorker.disableHttpHandler();
            port.postMessage(MessageUtils.generateSuccessMessage());

            break;
        case IS_AUTHENTICATED:
            if (!webWorker) {
                port.postMessage(MessageUtils.generateFailureMessage("Worker has not been initiated."));

                break;
            }

            try {
                port.postMessage(MessageUtils.generateSuccessMessage(webWorker.isAuthenticated()));
            } catch (error) {
                port.postMessage(MessageUtils.generateFailureMessage(error));
            }

            break;
        case GET_SIGN_OUT_URL:
            if (!webWorker) {
                port.postMessage(MessageUtils.generateFailureMessage("Worker has not been initiated."));

                break;
            }

            try {
                port.postMessage(MessageUtils.generateSuccessMessage(webWorker.getSignOutURL()));
            } catch (error) {
                port.postMessage(MessageUtils.generateFailureMessage(error));
            }

            break;
        case REFRESH_ACCESS_TOKEN:
            if (!webWorker) {
                port.postMessage(MessageUtils.generateFailureMessage("Worker has not been initiated."));

                break;
            }
            try {
                port.postMessage(MessageUtils.generateSuccessMessage(webWorker.refreshToken()));
            } catch (error) {
                port.postMessage(MessageUtils.generateFailureMessage(error));
            }

            break;
        default:
            port?.postMessage(MessageUtils.generateFailureMessage(`Unknown message type ${data?.type}`));
    }
};

const onRequestStartCallback = () => {
    ctx.postMessage({ type: REQUEST_START });
};

const onRequestSuccessCallback = (response: HttpResponse) => {
    ctx.postMessage({ data: JSON.stringify(response ?? ""), type: REQUEST_SUCCESS });
};

const onRequestFinishCallback = () => {
    ctx.postMessage({ type: REQUEST_FINISH });
};

const onRequestErrorCallback = (error: HttpError) => {
    const errorObject = { ...error };
    delete errorObject.toJSON;
    ctx.postMessage({ data: JSON.stringify(errorObject ?? ""), type: REQUEST_ERROR });
};

export default {} as typeof Worker & { new (): Worker };
