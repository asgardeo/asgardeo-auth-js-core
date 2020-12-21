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
import { AsgardeoAuthNetworkException } from "./network-exception";

export class AsgardeoAuthExceptionStack extends Error {
    public name: string;
    public code: string;
    public file: string;
    public method: string;
    public error: AsgardeoAuthException | AsgardeoAuthNetworkException | AsgardeoAuthExceptionStack;

    public constructor(
        code: string,
        file: string,
        method: string,
        error: AsgardeoAuthException | AsgardeoAuthNetworkException | AsgardeoAuthExceptionStack
    ) {
        super(error.message);
        this.name = this.constructor.name;
        this.code = code;
        this.file = file;
        this.method = method;
        Object.setPrototypeOf(this, new.target.prototype);
    }
}
