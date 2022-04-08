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

/**
 * JWK Model
 */
export interface JWKInterface {
    kty: string;
    e: string;
    use: string;
    kid: string;
    alg: string;
    n: string;
}

/**
 * The interface that defines the CryptoUtils methods.
 *
 * T is the type of the data passed as the argument into the `base64URLEncode` method.
 */
export interface CryptoUtils<T = any> {
    /**
     * Encode the provided data in base64url format.
     *
     * @param {T} value Data to be encoded.
     *
     * @returns {string} Encoded data.
     */
    base64URLEncode(value: T): string;

    /**
     * Decode the provided data encoded in base64url format.
     *
     * @param {string} value Data to be decoded.
     *
     * @returns {string} Decoded data.
     */
    base64URLDecode(value: string): string;

    /**
     * Generate random bytes.
     *
     * @param {number} length Length of the random bytes to be generated.
     *
     * @returns {T} Random bytes.
     */
    generateRandomBytes(length: number): T;

    /**
     * Hash the provided data using SHA-256.
     *
     * @param {string} data  Data to be hashed.
     *
     * @returns {T} Hashed data.
     */
    hashSha256(data: string): T;

    /**
     * Verify the provided JWT.
     *
     * @param {string} idToken ID Token to be verified.
     * @param {JWKInterface} jwk JWK to be used for verification.
     * @param {string[]} algorithms Algorithms to be used for verification.
     * @param {string} clientID Client ID to be used for verification.
     * @param {string} issuer Issuer to be used for verification.
     * @param {string} subject Subject to be used for verification.
     * @param {string} clockTolerance Clock tolerance to be used for verification.
     *
     * @returns {Promise<boolean>} True if the ID Token is valid.
     *
     * @throws {AsgardeoAuthException} if the id_token is invalid.
     */
    verifyJwt(
        idToken: string,
        jwk: JWKInterface,
        algorithms: string[],
        clientID: string,
        issuer: string,
        subject: string,
        clockTolerance?: number
    ): Promise<boolean>;
}
