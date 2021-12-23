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

import base64url from "base64url";
import sha256 from "fast-sha256";
// Importing from node_modules since rollup doesn't support export attribute of `package.json` yet.
import randombytes from "randombytes";
import parseJwk from "../../node_modules/jose/dist/browser/jwk/parse";
import jwtVerify, { KeyLike } from "../../node_modules/jose/dist/browser/jwt/verify";
import { AsgardeoAuthException } from "../exception";
import { DecodedIDTokenPayload, JWKInterface } from "../models";

export class CryptoUtils {
    // eslint-disable-next-line @typescript-eslint/no-empty-function
    private constructor() {}
    /**
     * Get URL encoded string.
     *
     * @returns {string} base 64 url encoded value.
     */
    public static base64URLEncode(value: Buffer | string): string {
        return base64url.encode(value).replace(/\+/g, "-").replace(/\//g, "_").replace(/=/g, "");
    }

    /**
     * Generate code verifier.
     *
     * @returns {string} code verifier.
     */
    public static getCodeVerifier(): string {
        return this.base64URLEncode(randombytes(32));
    }

    /**
     * Derive code challenge from the code verifier.
     *
     * @param {string} verifier.
     * @returns {string} code challenge.
     */
    public static getCodeChallenge(verifier: string): string {
        return this.base64URLEncode(new Buffer(sha256(new TextEncoder().encode(verifier))));
    }

    /**
     * Get the supported signing algorithms for the id_token.
     *
     * @returns {string[]} array of supported algorithms.
     */
    public static getSupportedSignatureAlgorithms(): string[] {
        return ["RS256", "RS512", "RS384", "PS256"];
    }

    /**
     * Get JWK used for the id_token
     *
     * @param {string} jwtHeader header of the id_token.
     * @param {JWKInterface[]} keys jwks response.
     * @returns {any} public key.
     */
    /* eslint-disable @typescript-eslint/no-explicit-any */
    public static getJWKForTheIdToken(jwtHeader: string, keys: JWKInterface[]): Promise<KeyLike> {
        const headerJSON = JSON.parse(base64url.decode(jwtHeader, "utf8"));

        for (const key of keys) {
            if (headerJSON.kid === key.kid) {
                return parseJwk({
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
    public static isValidIdToken(
        idToken: string,
        jwk: KeyLike,
        clientID: string,
        issuer: string,
        username: string,
        clockTolerance: number | undefined
    ): Promise<boolean> {
        return jwtVerify(idToken, jwk, {
            algorithms: this.getSupportedSignatureAlgorithms(),
            audience: clientID,
            clockTolerance: clockTolerance,
            issuer: issuer,
            subject: username
        })
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
    public static decodeIDToken(idToken: string): DecodedIDTokenPayload {
        try {
            const utf8String = base64url.decode(idToken.split(".")[1], "utf8");
            const payload = JSON.parse(utf8String);

            return payload;
        } catch (error) {
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
