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

import { ResponseMessage } from "../models";

export class MessageUtils {

    // eslint-disable-next-line @typescript-eslint/no-empty-function
    private constructor() { }

    /**
     * JSON stringifies the passed object.
     *
     * @param {any} data The data object.
     *
     * @return {ResponseMessage<string>} JSON string.
     */
    // eslint-disable-next-line @typescript-eslint/explicit-module-boundary-types
    public static generateSuccessMessage(data?: any): ResponseMessage<string>{
        return {
            blob: data?.data instanceof Blob ? data?.data : null,
            data: JSON.stringify(data ?? ""),
            success: true
        };
    }

    /**
     * JSON stringifies the passed object.
     *
     * @param {any} error The error object.
     *
     * @return {ResponseMessage<string>} JSON string.
     */
    // eslint-disable-next-line @typescript-eslint/explicit-module-boundary-types
    public static generateFailureMessage(error?: any): ResponseMessage<string> {
        if (error?.toJSON) {
            delete error.toJSON;
        }

        return {
            error: JSON.stringify(error ?? ""),
            success: false
        };
    }
}
