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

import { OIDCEndpoints } from "./oidc-provider-meta-data";
import { ResponseMode } from "../constants";
import { SERVER_ENVIRONMENTS } from "../constants/server-environments";

export interface DefaultAuthClientConfig {
    signInRedirectURL: string;
    signOutRedirectURL?: string;
    clientHost?: string;
    clientID: string;
    clientSecret?: string;
    enablePKCE?: boolean;
    prompt?: string;
    responseMode?: ResponseMode;
    scope?: string[];
    validateIDToken?: boolean;
    /**
     * Allowed leeway for id_tokens (in seconds).
     */
    clockTolerance?: number;
    /**
     * Specifies if cookies should be sent with access-token requests, refresh-token requests,
     * custom-grant requests, etc.
     *
     */
    sendCookiesInRequests?: boolean;
    /**
     * Specifies if a request to the `.well-known` endpoint should be made before a sign-in request.
     * Note that if this is set to false, then the needed endpoints should be provided through
     * the `endpoints` property.
     */
     environment?: SERVER_ENVIRONMENTS;
}

export interface WellKnownAuthClientConfig extends DefaultAuthClientConfig {
    wellKnownEndpoint: string;
    endpoints?: Partial<OIDCEndpoints>;
}

export interface OrganizationAuthClientConfig extends DefaultAuthClientConfig {
    organization: string;
    endpoints?: Partial<OIDCEndpoints>;
}

export interface ExplicitAuthClientConfig extends DefaultAuthClientConfig {
    endpoints: OIDCEndpoints
}

export type StrictAuthClientConfig = WellKnownAuthClientConfig | 
                OrganizationAuthClientConfig | ExplicitAuthClientConfig;

export type AuthClientConfig<T = unknown> = StrictAuthClientConfig & T;
