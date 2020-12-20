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

import { AsgardeoAuthException } from "./exception";

export class AsgardeoAuthNetworkException extends AsgardeoAuthException {
    public networkErrorCode: string;
    public networkErrorMessage: string;
    public status: number;
    public networkErrorData: string;

    public constructor(
        code: string,
        file: string,
        method: string,
        message: string,
        description: string,
        networkErrorCode: string,
        networkErrorMessage: string,
        status: number,
        networkErrorData: string
    ) {
        super(code, file, method, message, description);
        this.name = this.constructor.name;
        this.code = code;
        this.file = file;
        this.method = method;
        this.description = description;
        this.networkErrorCode = networkErrorCode;
        this.networkErrorMessage = networkErrorMessage;
        this.status = status;
        this.networkErrorData = networkErrorData;
        Object.setPrototypeOf(this, new.target.prototype);
    }
    tot;
}
