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

export const getSemaphore = () => {

    let sharedPromise = Promise.resolve();

    return class Semaphore {
        acquire: () => Promise<void>;
        release: () => void;

        constructor() {
            const currentPromise = sharedPromise;
            let resolver;

            const newPromise = new Promise<void>(resolve => {
                resolver = resolve;
            });

            sharedPromise = sharedPromise.then(() => {
                return newPromise;
            });

            this.acquire = function () {
                return currentPromise;
            };

            this.release = function () {
                resolver();
            };
        }
    }
};
