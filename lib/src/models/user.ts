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

export interface BasicUserInfo {
    email?: string | undefined;
    username?: string | undefined;
    displayName?: string | undefined;
    allowedScopes: string;
    tenantDomain?: string | undefined;
    sessionState: string;
    [ key: string ]: any;
}

/**
 * Interface of the authenticated user.
 */
export interface AuthenticatedUserInfo {
    /**
     * Authenticated user's display name.
     */
    displayName?: string | undefined;
    /**
     * Authenticated user's display name.
     * @deprecated Use `displayName` instead.
     */
    display_name?: string | undefined;
    /**
     * User's email.
     */
    email?: string | undefined;
    /**
     * Available scopes.
     */
    scope?: string | undefined;
    /**
     * Authenticated user's tenant domain.
     */
    tenantDomain?: string | undefined;
    /**
     * Authenticated user's username.
     */
    username: string;
    /**
     * The uid corresponding to the user who the ID token belonged to.
     */
    sub: string;
    [key: string]: any;
}
