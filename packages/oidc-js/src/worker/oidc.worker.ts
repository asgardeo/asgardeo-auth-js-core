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
    GET_AUTH_URL,
    GET_TOKEN,
    IS_AUTHENTICATED
} from "../constants";
import {
    HttpError,
    HttpResponse,
    SignInResponseWorker,
    WebWorkerClass,
    WebWorkerClientConfigInterface,
    WebWorkerInterface,
    SignInResponse,
    GetAuthorizationURLInterface,
    UserInfo
} from "../models";
import { generateFailureDTO, generateSuccessDTO } from "../utils";
import { WebWorker } from "./worker";

const ctx: WebWorkerClass<any> = self as any;

let webWorker;

ctx.onmessage = ({ data, ports }) => {
    const port = ports[0];
    console.log(data);
    console.log(webWorker);
    switch (data.type) {
        case INIT:
            try {
                const config: WebWorkerClientConfigInterface = { ...data.data };
                webWorker = WebWorker(config);
                webWorker.setHttpRequestError(onRequestErrorCallback);
                webWorker.setHttpRequestFinish(onRequestFinishCallback);
                webWorker.setHttpRequestStartCallback(onRequestStartCallback);
                webWorker.setHttpRequestSuccessCallback(onRequestSuccessCallback);
                port.postMessage(generateSuccessDTO());
            } catch (error) {
                console.log("worker init", error);
                port.postMessage(generateFailureDTO(error));
            }

            break;
        case GET_AUTH_URL:
            if (!webWorker) {
                port.postMessage(generateFailureDTO("Worker has not been initiated."));
            } else {
                webWorker
                    .getAuthorizationURL(data?.data)
                    .then((response: GetAuthorizationURLInterface) => {
                        port.postMessage(generateSuccessDTO(response));
                    })
                    .catch((error) => {
                        port.postMessage(generateFailureDTO(error));
                    });
            }

            break;
        case GET_TOKEN:
            if (!webWorker) {
                port.postMessage(generateFailureDTO("Worker has not been initiated."));
            } else {
                webWorker
                    .sendTokenRequest(data?.data?.code, data?.data?.sessionState, data?.data?.pkce)
                    .then((response: UserInfo) => {
                        port.postMessage(generateSuccessDTO(response));
                    })
                    .catch((error) => {
                        port.postMessage(generateFailureDTO(error));
                    });
            }

            break;
        case API_CALL:
            if (!webWorker) {
                port.postMessage(generateFailureDTO("Worker has not been initiated."));

                break;
            }

            if (!webWorker.isAuthenticated()) {
                port.postMessage(generateFailureDTO("You have not signed in yet."));
            } else {
                webWorker
                    .httpRequest(data.data)
                    .then((response) => {
                        port.postMessage(generateSuccessDTO(response));
                    })
                    .catch((error) => {
                        port.postMessage(generateFailureDTO(error));
                    });
            }

            break;
        case API_CALL_ALL:
            if (!webWorker) {
                port.postMessage(generateFailureDTO("Worker has not been initiated."));

                break;
            }

            if (!webWorker.isAuthenticated()) {
                port.postMessage(generateFailureDTO("You have not signed in yet."));
            } else {
                webWorker
                    .httpRequestAll(data.data)
                    .then((response) => {
                        port.postMessage(generateSuccessDTO(response));
                    })
                    .catch((error) => {
                        port.postMessage(generateFailureDTO(error));
                    });
            }

            break;
        case LOGOUT:
            if (!webWorker) {
                port.postMessage(generateFailureDTO("Worker has not been initiated."));

                break;
            }

            if (!webWorker.isAuthenticated()) {
                port.postMessage(generateFailureDTO("You have not signed in yet."));
            } else {
                try {
                    port.postMessage(generateSuccessDTO(webWorker.signOut()));
                } catch (error) {
                    port.postMessage(generateFailureDTO(error));
                }
            }

            break;
        case CUSTOM_GRANT:
            if (!webWorker) {
                port.postMessage(generateFailureDTO("Worker has not been initiated."));

                break;
            }

            if (!webWorker.isAuthenticated() && data.data.signInRequired) {
                port.postMessage(generateFailureDTO("You have not signed in yet."));

                break;
            }

            webWorker
                .customGrant(data.data)
                .then((response) => {
                    port.postMessage(generateSuccessDTO(response));
                })
                .catch((error) => {
                    port.postMessage(generateFailureDTO(error));
                });

            break;
        case END_USER_SESSION:
            if (!webWorker) {
                port.postMessage(generateFailureDTO("Worker has not been initiated."));

                break;
            }

            if (!webWorker.isAuthenticated() && data.data.signInRequired) {
                port.postMessage(generateFailureDTO("You have not signed in yet."));

                break;
            }

            webWorker
                .endUserSession()
                .then((response) => {
                    port.postMessage(generateSuccessDTO(response));
                })
                .catch((error) => {
                    port.postMessage(generateFailureDTO(error));
                });
            break;
        case GET_SERVICE_ENDPOINTS:
            if (!webWorker) {
                port.postMessage(generateFailureDTO("Worker has not been initiated."));

                break;
            }

            webWorker
                .getServiceEndpoints()
                .then((response) => {
                    port.postMessage(generateSuccessDTO(response));
                })
                .catch((error) => {
                    port.postMessage(generateFailureDTO(error));
                });

            break;
        case GET_USER_INFO:
            if (!webWorker) {
                port.postMessage(generateFailureDTO("Worker has not been initiated."));

                break;
            }

            if (!webWorker.isAuthenticated() && data.data.signInRequired) {
                port.postMessage(generateFailureDTO("You have not signed in yet."));

                break;
            }

            try {
                port.postMessage(generateSuccessDTO(webWorker.getUserInfo()));
            } catch (error) {
                port.postMessage(generateFailureDTO(error));
            }

            break;
        case GET_DECODED_ID_TOKEN:
            if (!webWorker) {
                port.postMessage(generateFailureDTO("Worker has not been initiated."));

                break;
            }

            if (!webWorker.isAuthenticated() && data.data.signInRequired) {
                port.postMessage(generateFailureDTO("You have not signed in yet."));

                break;
            }

            try {
                port.postMessage(generateSuccessDTO(webWorker.getDecodedIDToken()));
            } catch (error) {
                port.postMessage(generateFailureDTO(error));
            }

            break;
        case ENABLE_HTTP_HANDLER:
            if (!webWorker) {
                port.postMessage(generateFailureDTO("Worker has not been initiated."));

                break;
            }

            webWorker.enableHttpHandler();
            port.postMessage(generateSuccessDTO());

            break;
        case DISABLE_HTTP_HANDLER:
            if (!webWorker) {
                port.postMessage(generateFailureDTO("Worker has not been initiated."));

                break;
            }

            webWorker.disableHttpHandler();
            port.postMessage(generateSuccessDTO());

            break;
        case IS_AUTHENTICATED:
            if (!webWorker) {
                port.postMessage(generateFailureDTO("Worker has not been initiated."));

                break;
            }

            try {
                port.postMessage(generateSuccessDTO(webWorker.isAuthenticated()));
            } catch (error) {
                port.postMessage(generateFailureDTO(error));
            }

            break;
        default:
            port?.postMessage(generateFailureDTO(`Unknown message type ${data?.type}`));
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
