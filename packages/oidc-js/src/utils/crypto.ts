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

import Base64 from "crypto-js/enc-base64";
import WordArray from "crypto-js/lib-typedarrays";
import sha256 from "crypto-js/sha256";
import { JWKInterface } from "../models";
import jwtVerify, { KeyLike } from "../../node_modules/jose/dist/browser/jwt/verify";
import parseJwk from "../../node_modules/jose/dist/browser/jwk/parse";

/**
 * Get URL encoded string.
 *
 * @param {CryptoJS.WordArray} value.
 * @returns {string} base 64 url encoded value.
 */
export const base64URLEncode = (value: CryptoJS.WordArray): string => {
    return Base64.stringify(value)
        .replace(/\+/g, "-")
        .replace(/\//g, "_")
        .replace(/=/g, "");
};

/**
 * Generate code verifier.
 *
 * @returns {string} code verifier.
 */
export const getCodeVerifier = (): string => {
    return base64URLEncode(WordArray.random(32));
};

/**
 * Derive code challenge from the code verifier.
 *
 * @param {string} verifier.
 * @returns {string} code challenge.
 */
export const getCodeChallenge = (verifier: string): string => {
    return base64URLEncode(sha256(verifier));
};

/**
 * Get the supported signing algorithms for the id_token.
 *
 * @returns {string[]} array of supported algorithms.
 */
export const getSupportedSignatureAlgorithms = (): string[] => {
    return ["RS256", "RS512", "RS384", "PS256"];
};

/**
 * Get JWK used for the id_token
 *
 * @param {string} jwtHeader header of the id_token.
 * @param {JWKInterface[]} keys jwks response.
 * @returns {any} public key.
 */
/* eslint-disable @typescript-eslint/no-explicit-any */
export const getJWKForTheIdToken = (jwtHeader: string, keys: JWKInterface[]): Promise<KeyLike> => {
    const headerJSON = JSON.parse(atob(jwtHeader));

    for (const key of keys) {
        if (headerJSON.kid === key.kid) {
            return parseJwk({
                kty: key.kty,
                e: key.e,
                n: key.n,
                alg: key.alg
            });
        }
    }

    return Promise.reject(
        "Failed to find the 'kid' specified in the id_token. 'kid' found in the header : " +
            headerJSON.kid +
            ", Expected values: " +
            keys.map((key) => key.kid).join(", ")
    );
};

/**
 * Verify id token.
 *
 * @param idToken id_token received from the IdP.
 * @param jwk public key used for signing.
 * @param {string} clientID app identification.
 * @param {string} issuer id_token issuer.
 * @returns {Promise<boolean>} whether the id_token is valid.
 */
export const isValidIdToken = (
    idToken: string,
    jwk: KeyLike,
    clientID: string,
    issuer: string,
    username: string
): Promise<boolean> => {
    return jwtVerify(idToken, jwk, {
        issuer: issuer,
        audience: clientID,
        subject: username,
        algorithms: getSupportedSignatureAlgorithms()
    }).then(() => {
        return Promise.resolve(true)
    }).catch((error) => {
        return Promise.reject(error);
    })
};
