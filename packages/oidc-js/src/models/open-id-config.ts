/**
 * Copyright (c) 2020, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * WSO2 Inc. licenses this file to you under the Apache License;
 * Version 2.0 (the License); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing;
 * software distributed under the License is distributed on an
 * AS IS BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

export interface OpenIDConfig {
    request_parameter_supported: boolean;
    claims_parameter_supported: boolean;
    introspection_endpoint: string;
    Response_modes_supported: string[];
    scopes_supported: string[];
    check_session_iframe: string;
    backchannel_logout_supported: boolean;
    issuer: string;
    authorization_endpoint: string;
    introspection_endpoint_auth_methods_supported: string[];
    claims_supported: string[];
    userinfo_signing_alg_values_supported: string[];
    token_endpoint_auth_methods_supported: string[];
    response_modes_supported: string[];
    backchannel_logout_session_supported: boolean;
    token_endpoint: string;
    response_types_supported: string[];
    revocation_endpoint_auth_methods_supported: string[];
    grant_types_supported: string[];
    end_session_endpoint: string;
    revocation_endpoint: string;
    userinfo_endpoint: string;
    code_challenge_methods_supported: string[];
    jwks_uri: string;
    subject_types_supported: string[];
    id_token_signing_alg_values_supported: string[];
    registration_endpoint: string;
    request_object_signing_alg_values_supported: string[];
}
