/**
 * Copyright (c) 2022, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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

export class CryptoHelper<T = any> {
    private _cryptoUtils: CryptoUtils<T>;

    public constructor(cryptoUtils: CryptoUtils<T>) {
        this._cryptoUtils = cryptoUtils;
    }

    /**
     * Generate code verifier.
     *
     * @return {string} code verifier.
     */
    public getCodeVerifier(): string {
        return this._cryptoUtils.base64URLEncode(this._cryptoUtils.generateRandomBytes(32));
    }

    /**
     * Derive code challenge from the code verifier.
     *
     * @param {string} verifier.
     *
     * @return {string} code challenge.
     */
    public getCodeChallenge(verifier: string): string {
        return this._cryptoUtils.base64URLEncode(this._cryptoUtils.hashSha256(verifier));
    }

    /**
     * Get JWK used for the id_token
     *
     * @param {string} jwtHeader header of the id_token.
     * @param {JWKInterface[]} keys jwks response.
     *
     * @return {JWKInterface} public key.
     *
     * @throws {AsgardeoAuthException}
     */
    /* eslint-disable @typescript-eslint/no-explicit-any */
    public getJWKForTheIdToken(jwtHeader: string, keys: JWKInterface[]): JWKInterface {
        const headerJSON = JSON.parse(this._cryptoUtils.base64URLDecode(jwtHeader));

        for (const key of keys) {
            if (headerJSON.kid === key.kid) {
                return key;
            }
        }

        throw new AsgardeoAuthException(
            "JS-CRYPTO_UTIL-GJFTIT-IV01",
            "kid not found.",
            "Failed to find the 'kid' specified in the id_token. 'kid' found in the header : " +
            headerJSON.kid +
            ", Expected values: " +
            keys.map((key) => key.kid).join(", ")
        );
    }

    /**
     * Verify id token.
     *
     * @param idToken id_token received from the IdP.
     * @param {JWKInterface} jwk public key used for signing.
     * @param {string} clientID app identification.
     * @param {string} issuer id_token issuer.
     * @param {string} username Username.
     * @param {number} clockTolerance - Allowed leeway for id_tokens (in seconds).
     *
     * @return {Promise<boolean>} whether the id_token is valid.
     *
     * @throws {AsgardeoAuthException} if the id_token is invalid.
     */
    public isValidIdToken(
        idToken: string,
        jwk: JWKInterface,
        clientID: string,
        issuer: string,
        username: string,
        clockTolerance: number | undefined
    ): Promise<boolean> {
        return this._cryptoUtils
            .verifyJwt(idToken, jwk, SUPPORTED_SIGNATURE_ALGORITHMS, clientID, issuer, username, clockTolerance)
            .then((response: boolean) => {
                if (response) {
                    return Promise.resolve(true);
                }

                return Promise.reject(
                    new AsgardeoAuthException(
                        "JS-CRYPTO_HELPER-IVIT-IV01",
                        "Invalid ID token.",
                        "ID token validation returned false"
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
     *
     * @throws {AsgardeoAuthException}
     */
    public decodeIDToken(idToken: string): DecodedIDTokenPayload {
        try {
            const utf8String = this._cryptoUtils.base64URLDecode(idToken.split(".")[ 1 ]);
            const payload = JSON.parse(utf8String);

            return payload;
        } catch (error: any) {
            throw new AsgardeoAuthException("JS-CRYPTO_UTIL-DIT-IV01", "Decoding ID token failed.", error);
        }
    }
}
