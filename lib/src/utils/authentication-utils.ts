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

import { PKCE_CODE_VERIFIER, PKCE_SEPARATOR } from "../constants";
import { DecodedIDTokenPayload } from "../models";

export class AuthenticationUtils {
    // eslint-disable-next-line @typescript-eslint/no-empty-function
    private constructor() {}

    public static filterClaimsFromIDTokenPayload(payload: DecodedIDTokenPayload): any {
        const optionalizedPayload: Partial<DecodedIDTokenPayload> = { ...payload };

        delete optionalizedPayload?.iss;
        delete optionalizedPayload?.aud;
        delete optionalizedPayload?.exp;
        delete optionalizedPayload?.iat;
        delete optionalizedPayload?.acr;
        delete optionalizedPayload?.amr;
        delete optionalizedPayload?.azp;
        delete optionalizedPayload?.auth_time;
        delete optionalizedPayload?.nonce;
        delete optionalizedPayload?.c_hash;
        delete optionalizedPayload?.at_hash;
        delete optionalizedPayload?.nbf;
        delete optionalizedPayload?.isk;
        delete optionalizedPayload?.sid;

        const camelCasedPayload = {};
        Object.entries(optionalizedPayload).forEach(([key, value]) => {
            const keyParts = key.split("_");
            const camelCasedKey = keyParts
                .map((key: string, index: number) => {
                    if (index === 0) {
                        return key;
                    }

                    return [key[0].toUpperCase(), ...key.slice(1)].join("");
                })
                .join("");

            camelCasedPayload[camelCasedKey] = value;
        });

        return camelCasedPayload;
    }

    /**
     * @deprecated since v1.0.6 and will be removed with the v2.0.0 release.
     */
    public static getTenantDomainFromIdTokenPayload = (
        payload: DecodedIDTokenPayload,
        uidSeparator: string = "@"
    ): string => {
        // Try to extract the tenant domain from the `sub` claim.
        const uid = payload.sub;
        const tokens = uid.split(uidSeparator);

        // This works only when the email is used as the username
        // and the tenant domain is appended to the`sub` attribute.
        return tokens.length > 2 ? tokens[tokens.length - 1] : "";
    };

    public static getTokenRequestHeaders(): HeadersInit {
        return {
            Accept: "application/json",
            "Content-Type": "application/x-www-form-urlencoded"
        };
    }

    /**
     * This generates the state param value to be sent with an authorization request.
     *
     * @param {string} pkceKey The PKCE key.
     * @param {string} state The state value to be passed. (The correlation ID will be appended to this state value.)
     *
     * @returns {string} The state param value.
     */
    public static generateStateParamForRequestCorrelation(pkceKey: string, state?: string): string {
        const index: number = parseInt(pkceKey.split(PKCE_SEPARATOR)[1]);

        return state ? `${state}_request_${index}` : `request_${index}`;
    }

    public static extractPKCEKeyFromStateParam(stateParam: string): string {
        const index: number = parseInt(stateParam.split("request_")[1]);

        return `${PKCE_CODE_VERIFIER}${PKCE_SEPARATOR}${index}`;
    }
}
