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

import { WebWorkerCore } from "./worker-core";
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
import { AuthClientConfig, BasicUserInfo } from "../core";
import { AsgardeoSPAException } from "../exception";
import {
    AuthorizationResponse,
    HttpError,
    HttpResponse,
    WebWorkerClass,
    WebWorkerClientConfig,
    WebWorkerCoreInterface
} from "../models";
import { MessageUtils } from "../utils";

const ctx: WebWorkerClass<any> = self as any;

let webWorker: WebWorkerCoreInterface;

ctx.onmessage = ({ data, ports }) => {
    const port = ports[0];
    if (data.type !== INIT && !webWorker) {
        port.postMessage(
            MessageUtils.generateFailureMessage(
                new AsgardeoSPAException(
                    "CLIENT_WORKER-ONMSG-NF01",
                    "client.worker",
                    data.type,
                    "The web worker has not been initialized yet.",
                    "The initialize method needs to be called before the specified operation can be carried out."
                )
            )
        );

        return;
    }

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
            webWorker
                .getAuthorizationURL(data?.data?.params, data?.data?.signInRedirectURL)
                .then((response: AuthorizationResponse) => {
                    port.postMessage(MessageUtils.generateSuccessMessage(response));
                })
                .catch((error) => {
                    port.postMessage(MessageUtils.generateFailureMessage(error));
                });

            break;
        case REQUEST_ACCESS_TOKEN:
            webWorker
                .requestAccessToken(data?.data?.code, data?.data?.sessionState, data?.data?.pkce)
                .then((response: BasicUserInfo) => {
                    port.postMessage(MessageUtils.generateSuccessMessage(response));
                })
                .catch((error) => {
                    port.postMessage(MessageUtils.generateFailureMessage(error));
                });

            break;
        case HTTP_REQUEST:
            webWorker
                .httpRequest(data.data)
                .then((response) => {
                    port.postMessage(MessageUtils.generateSuccessMessage(response));
                })
                .catch((error) => {
                    port.postMessage(MessageUtils.generateFailureMessage(error));
                });

            break;
        case HTTP_REQUEST_ALL:
            webWorker
                .httpRequestAll(data.data)
                .then((response) => {
                    port.postMessage(MessageUtils.generateSuccessMessage(response));
                })
                .catch((error) => {
                    port.postMessage(MessageUtils.generateFailureMessage(error));
                });

            break;
        case SIGN_OUT:
            try {
                port.postMessage(MessageUtils.generateSuccessMessage(webWorker.signOut(data?.data)));
            } catch (error) {
                port.postMessage(MessageUtils.generateFailureMessage(error));
            }

            break;
        case REQUEST_CUSTOM_GRANT:
            webWorker
                .requestCustomGrant(data.data)
                .then((response) => {
                    port.postMessage(MessageUtils.generateSuccessMessage(response));
                })
                .catch((error) => {
                    port.postMessage(MessageUtils.generateFailureMessage(error));
                });

            break;
        case REVOKE_ACCESS_TOKEN:
            webWorker
                .revokeAccessToken()
                .then((response) => {
                    port.postMessage(MessageUtils.generateSuccessMessage(response));
                })
                .catch((error) => {
                    port.postMessage(MessageUtils.generateFailureMessage(error));
                });
            break;
        case GET_OIDC_SERVICE_ENDPOINTS:
            try {
                port.postMessage(MessageUtils.generateSuccessMessage(webWorker.getOIDCServiceEndpoints()));
            } catch (error) {
                port.postMessage(MessageUtils.generateFailureMessage(error));
            }

            break;
        case GET_BASIC_USER_INFO:
            try {
                port.postMessage(MessageUtils.generateSuccessMessage(webWorker.getBasicUserInfo()));
            } catch (error) {
                port.postMessage(MessageUtils.generateFailureMessage(error));
            }

            break;
        case GET_DECODED_ID_TOKEN:
            try {
                port.postMessage(MessageUtils.generateSuccessMessage(webWorker.getDecodedIDToken()));
            } catch (error) {
                port.postMessage(MessageUtils.generateFailureMessage(error));
            }

            break;
        case ENABLE_HTTP_HANDLER:
            webWorker.enableHttpHandler();
            port.postMessage(MessageUtils.generateSuccessMessage());

            break;
        case DISABLE_HTTP_HANDLER:
            webWorker.disableHttpHandler();
            port.postMessage(MessageUtils.generateSuccessMessage());

            break;
        case IS_AUTHENTICATED:
            try {
                port.postMessage(MessageUtils.generateSuccessMessage(webWorker.isAuthenticated()));
            } catch (error) {
                port.postMessage(MessageUtils.generateFailureMessage(error));
            }

            break;
        case GET_SIGN_OUT_URL:
            try {
                port.postMessage(MessageUtils.generateSuccessMessage(webWorker.getSignOutURL()));
            } catch (error) {
                port.postMessage(MessageUtils.generateFailureMessage(error));
            }

            break;
        case REFRESH_ACCESS_TOKEN:
            try {
                port.postMessage(MessageUtils.generateSuccessMessage(webWorker.refreshAccessToken()));
            } catch (error) {
                port.postMessage(MessageUtils.generateFailureMessage(error));
            }

            break;
        case START_AUTO_REFRESH_TOKEN:
            try {
                port.postMessage(MessageUtils.generateSuccessMessage(webWorker.startAutoRefreshToken()));
            } catch (error) {
                port.postMessage(MessageUtils.generateFailureMessage(error));
            }

            break;
        case SET_SESSION_STATE:
            try {
                port.postMessage(MessageUtils.generateSuccessMessage(webWorker.setSessionState(data?.data)));
            } catch (error) {
                port.postMessage(MessageUtils.generateFailureMessage(error));
            }

            break;
        default:
            port?.postMessage(MessageUtils.generateFailureMessage(new AsgardeoSPAException(
                "CLIENT_WORKER-ONMSG-IV02",
                "client.worker",
                "onmessage",
                "The message type is invalid.",
                `The message type provided, ${data.type}, is invalid.`
            )));
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
