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

import { getEndSessionEndpoint, resetOPConfiguration } from "./op-config";
import { endAuthenticatedSession, getSessionParameter } from "./session-storage";
import {
    ID_TOKEN,
    LOGOUT_SUCCESS,
    SIGN_OUT_REDIRECT_URL
} from "../constants";
import { Storage } from "../constants/storage";
import { ConfigInterface, WebWorkerConfigInterface, isWebWorkerConfig } from "../models";

/**
 * Execute user sign out request
 *
 * @param {object} requestParams
 * @param {function} callback
 * @returns {Promise<any>} sign out request status
 */
/* eslint-disable @typescript-eslint/no-explicit-any */
export function sendSignOutRequest(requestParams: ConfigInterface | WebWorkerConfigInterface): Promise<any> {
    const logoutEndpoint = getEndSessionEndpoint(requestParams);

    if (!logoutEndpoint || logoutEndpoint.trim().length === 0) {
        return Promise.reject(new Error("No logout endpoint found in the session."));
    }

    const idToken = getSessionParameter(ID_TOKEN, requestParams);

    if (!idToken || idToken.trim().length === 0) {
        return Promise.reject(new Error("Invalid id_token found in the session."));
    }

    const callbackURL = getSessionParameter(SIGN_OUT_REDIRECT_URL, requestParams);

    if (!callbackURL || callbackURL.trim().length === 0) {
        return Promise.reject(new Error("No callback URL found in the session."));
    }

    endAuthenticatedSession(requestParams);
    resetOPConfiguration(requestParams);

    const logoutCallback =
        `${ logoutEndpoint }?` + `id_token_hint=${ idToken }` + `&post_logout_redirect_uri=${ callbackURL }&state=`
        + LOGOUT_SUCCESS;

    if (requestParams.storage !== Storage.WebWorker) {
        window.location.href = logoutCallback;

        return Promise.resolve(true);
    } else {
        return Promise.resolve(logoutCallback);
    }
}

/**
 * Handle sign out requests
 *
 * @param {object} requestParams
 * @param {function} callback
 * @returns {Promise<any>} sign out status
 */
/* eslint-disable @typescript-eslint/no-explicit-any */
export function handleSignOut(requestParams: ConfigInterface | WebWorkerConfigInterface): Promise<any> {
    if (
        (requestParams.storage === Storage.SessionStorage && sessionStorage.length === 0) ||
        (requestParams.storage === Storage.LocalStorage && localStorage.length === 0)
    ) {
        return Promise.reject(new Error("No login sessions."));
    } else if (isWebWorkerConfig(requestParams) && requestParams?.session?.size === 0) {
        return Promise.reject(new Error("No login sessions."));
    } else {
        return sendSignOutRequest(requestParams);
    }
}

/**
 * Checks if the user has logged out and returns true if the logout is successful.
 *
 * @return {boolean} isLoggedOut - Specifies if a user has logged out or not.
 */
export const isLoggedOut = (): boolean => {
    const param = new URL(window.location.href).searchParams.get("state");
    const isLoggedOut = param && param === LOGOUT_SUCCESS;

    if (isLoggedOut) {
        const url = new URL(window.location.href);
        const searchParams = new URLSearchParams(url.search.slice(1));

        searchParams.delete("state");

        const newUrl = window.location.href.split("?")[ 0 ] + "?" + searchParams.toString();

        history.pushState({}, document.title, newUrl);
    }

    return isLoggedOut;
}
