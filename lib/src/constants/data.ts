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

export enum Stores {
    ConfigData = "config_data",
    OIDCProviderMetaData = "oidc_provider_meta_data",
    SessionData = "session_data",
    TemporaryData = "temporary_data"
}

export const REFRESH_TOKEN_TIMER = "refresh_token_timer";
export const PKCE_CODE_VERIFIER = "pkce_code_verifier";
export const PKCE_SEPARATOR = "#";

export const SUPPORTED_SIGNATURE_ALGORITHMS = [
    "RS256", "RS512", "RS384", "PS256"
];
