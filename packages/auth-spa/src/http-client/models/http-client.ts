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
 *
 */

/**
 * Http client interface with static functions.
 */
export interface HttpClientStatic<S> {
    getInstance(): S;
}

/**
 * Http client interface.
 */
export interface HttpClientInterface<T, U, V> {
    init(isHandlerEnabled: boolean,
         attachToken: () => Promise<void>,
         requestStartCallback: () => void,
         requestSuccessCallback: (response: U) => void,
         requestErrorCallback: (error: V) => void,
         requestFinishCallback: () => void
    ): Promise<void>
    disableHandler: () => void;
    disableHandlerWithTimeout: (timeout: number) => void;
    enableHandler: () => void;
    errorHandler(error: V): V;
    requestHandler(request: T): Promise<T>;
    successHandler(response: U): U;
}
