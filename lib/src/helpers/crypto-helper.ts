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

import { SUPPORTED_SIGNATURE_ALGORITHMS } from "../constants";
import { AsgardeoAuthException } from "../exception";
import { CryptoUtils, DecodedIDTokenPayload, JWKInterface } from "../models";

export class CryptoHelper<T = any, R = any> {
    private _cryptoUtils: CryptoUtils<T, R>;

    public constructor(cryptoUtils: CryptoUtils<T, R>) {
        this._cryptoUtils = cryptoUtils;
    }

    /**
     * Generate code verifier.
     *
     * @returns {string} code verifier.
     */
    public getCodeVerifier(): string {
        return this._cryptoUtils.base64URLEncode(this._cryptoUtils.generateRandomBytes(32));
    }

    /**
     * Derive code challenge from the code verifier.
     *
     * @param {string} verifier.
     * @returns {string} code challenge.
     */
    public getCodeChallenge(verifier: string): string {
        return this._cryptoUtils.base64URLEncode(this._cryptoUtils.hashSha256(verifier));
    }

    /**
     * Get JWK used for the id_token
     *
     * @param {string} jwtHeader header of the id_token.
     * @param {JWKInterface[]} keys jwks response.
     * @returns {any} public key.
     */
    /* eslint-disable @typescript-eslint/no-explicit-any */
    public getJWKForTheIdToken(jwtHeader: string, keys: JWKInterface[]): Promise<R> {
        const headerJSON = JSON.parse(this._cryptoUtils.base64URLDecode(jwtHeader));

        for (const key of keys) {
            if (headerJSON.kid === key.kid) {
                return this._cryptoUtils.parseJwk({
                    alg: key.alg,
                    e: key.e,
                    kty: key.kty,
                    n: key.n
                });
            }
        }

        return Promise.reject(
            new AsgardeoAuthException(
                "CRYPTO_UTIL-GTFTIT-IV01",
                "crypto-utils",
                "getJWKForTheIdToken",
                "kid not found.",
                "Failed to find the 'kid' specified in the id_token. 'kid' found in the header : " +
                    headerJSON.kid +
                    ", Expected values: " +
                    keys.map((key) => key.kid).join(", ")
            )
        );
    }

    /**
     * Verify id token.
     *
     * @param idToken id_token received from the IdP.
     * @param jwk public key used for signing.
     * @param {string} clientID app identification.
     * @param {string} issuer id_token issuer.
     * @param {string} username Username.
     * @param {number} clockTolerance - Allowed leeway for id_tokens (in seconds).
     * @returns {Promise<boolean>} whether the id_token is valid.
     */
    public isValidIdToken(
        idToken: string,
        jwk: R,
        clientID: string,
        issuer: string,
        username: string,
        clockTolerance: number | undefined
    ): Promise<boolean> {
        return this._cryptoUtils
            .verifyJwt(idToken, jwk, SUPPORTED_SIGNATURE_ALGORITHMS, clientID, issuer, username, clockTolerance)
            .then(() => {
                return Promise.resolve(true);
            })
            .catch((error) => {
                return Promise.reject(
                    new AsgardeoAuthException(
                        "CRYPTO_UTIL-IVIT-IV02",
                        "crypto-utils",
                        "isValidIdToken",
                        "Validating ID token failed",
                        error
                    )
                );
            });
    }

    /**
     * This function decodes the payload of an id token and returns it.
     *
     * @param {string} idToken - The id token to be decoded.
     *
     * @return {DecodedIdTokenPayloadInterface} - The decoded payload of the id token.
     */
    public decodeIDToken(idToken: string): DecodedIDTokenPayload {
        try {
            const utf8String = this._cryptoUtils.base64URLDecode(idToken.split(".")[1]);
            const payload = JSON.parse(utf8String);

            return payload;
        } catch (error: any) {
            throw new AsgardeoAuthException(
                "CRYPTO_UTIL-DIT-IV01",
                "crypto-utils",
                "decodeIDToken",
                "Decoding ID token failed.",
                error
            );
        }
    }
}
