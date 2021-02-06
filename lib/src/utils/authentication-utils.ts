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

import { CryptoUtils } from "./crypto-utils";
import { AuthenticatedUserInfo, DecodedIDTokenPayload, TokenRequestHeader } from "../models";

export class AuthenticationUtils {
    // eslint-disable-next-line @typescript-eslint/no-empty-function
    private constructor() {}

    public static getAuthenticatedUserInfo(idToken: string): AuthenticatedUserInfo {
        const payload: DecodedIDTokenPayload = CryptoUtils.decodeIDToken(idToken);
        const tenantDomain: string = this.getTenantDomainFromIdTokenPayload(payload);
        const username: string = this.extractUserName(payload);

        const givenName: string = payload.given_name ?? "";
        const familyName: string = payload.family_name ?? "";
        const fullName: string =
            givenName && familyName
                ? `${givenName} ${familyName}`
                : givenName
                ? givenName
                : familyName
                ? familyName
                : "";
        const displayName: string = payload.preferred_username ?? fullName;

        return {
            displayName: displayName,
            tenantDomain,
            username: username,
            ...this.filterClaimsFromIDTokenPayload(payload)
        };
    }

    private static filterClaimsFromIDTokenPayload(payload: DecodedIDTokenPayload) {
        delete payload?.iss;
        delete payload?.sub;
        delete payload?.aud;
        delete payload?.exp;
        delete payload?.iat;
        delete payload?.acr;
        delete payload?.amr;
        delete payload?.azp;
        delete payload?.auth_time;
        delete payload?.nonce;
        delete payload?.c_hash;
        delete payload?.at_hash
        delete payload?.nbf;
        delete payload?.isk;
        delete payload?.sid;

        const camelCasedPayload = {}
        Object.entries(payload).forEach(([ key, value ]) => {
            const keyParts = key.split("_");
            const camelCasedKey = keyParts.map((key: string, index: number) => {
                if (index === 0) {
                    return key;
                }

                return [ key[ 0 ].toUpperCase(), ...key.slice(1) ].join("");
            }).join("");

            camelCasedPayload[ camelCasedKey ] = value;
        });

        return camelCasedPayload;
    }

    public static extractUserName = (payload: DecodedIDTokenPayload, uidSeparator: string = "@"): string => {
        const uid = payload.sub;
        const parts = uid.split(uidSeparator);

        parts.length > 2 && parts.pop();

        return parts.join(uidSeparator);
    };

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

    public static getTokenRequestHeaders(): TokenRequestHeader {
        return {
            Accept: "application/json",
            "Content-Type": "application/x-www-form-urlencoded"
        };
    }
}
