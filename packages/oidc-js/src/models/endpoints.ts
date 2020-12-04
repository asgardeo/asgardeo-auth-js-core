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

/**
 * The interface of the OpenID Provider Metadata values used by OIDC.
 */
export interface OIDCProviderMetaData {
    /**
     * URL using the https scheme with no query or fragment component that the OP asserts as its Issuer Identifier.
     */
    issuer: string;
    /**
     * URL of the OP's OAuth 2.0 Authorization Endpoint.
     */
    authorization_endpoint: string;
    /**
     * URL of the OP's OAuth 2.0 Token Endpoint.
     */
    token_endpoint: string;
    /**
     * URL of the OP's UserInfo Endpoint.
     */
    userinfo_endpoint: string;
    /**
     * URL of the OP's JSON Web Key Set [JWK] document.
     * This contains the signing key(s) the RP uses to validate signatures from the OP.
     */
    jwks_uri: string;
    /**
     * URL of the OP's Dynamic Client Registration Endpoint
     */
    registration_endpoint: string;
    /**
     * JSON array containing a list of the OAuth 2.0 [RFC6749] scope values that this server supports.
     */
    scopes_supported: string[];
    /**
     * JSON array containing a list of the OAuth 2.0 response_type values that this OP supports.
     */
    response_types_supported: string[];
    /**
     *  JSON array containing a list of the OAuth 2.0 response_mode values that this OP supports.
     */
    response_modes_supported?: string[];
    /**
     * JSON array containing a list of the OAuth 2.0 Grant Type values that this OP supports.
     */
    grant_types_supported?: string[];
    /**
     * JSON array containing a list of the Authentication Context Class References that this OP supports.
     */
    acr_values_supported?: string[];
    /**
     * JSON array containing a list of the Subject Identifier types that this OP supports.
     */
    subject_types_supported: string[];
    /**
     * JSON array containing a list of the JWS signing algorithms (alg values)
     * supported by the OP for the ID Token to encode the Claims in a JWT [JWT].
     */
    id_token_signing_alg_values_supported: string[];
    /**
     * JSON array containing a list of the JWE encryption algorithms (alg values)
     * supported by the OP for the ID Token to encode the Claims in a JWT [JWT].
     */
    id_token_encryption_alg_values_supported?: string[];
    /**
     * JSON array containing a list of the JWE encryption algorithms (enc values)
     * supported by the OP for the ID Token to encode the Claims in a JWT [JWT].
     */
    id_token_encryption_enc_values_supported?: string[];
    /**
     * JSON array containing a list of the JWS [JWS] signing algorithms (alg values) [JWA]
     * supported by the UserInfo Endpoint to encode the Claims in a JWT [JWT].
     */
    userinfo_signing_alg_values_supported?: string[];
    /**
     * JSON array containing a list of the JWE [JWE] encryption algorithms (alg values)
     * [JWA] supported by the UserInfo Endpoint to encode the Claims in a JWT [JWT].
     */
    userinfo_encryption_alg_values_supported?: string[];
    /**
     * JSON array containing a list of the JWE encryption algorithms (enc values) [JWA]
     * supported by the UserInfo Endpoint to encode the Claims in a JWT [JWT]
     */
    userinfo_encryption_enc_values_supported?: string[];
    /**
     * JSON array containing a list of the JWS signing algorithms (alg values) supported by the OP for Request Objects
     */
    request_object_signing_alg_values_supported?: string[];
    /**
     * JSON array containing a list of the JWE encryption algorithms (alg values)
     * supported by the OP for Request Objects.
     */
    request_object_encryption_alg_values_supported?: string[];
    /**
     * JSON array containing a list of the JWE encryption algorithms (enc values)
     * supported by the OP for Request Objects.
     */
    request_object_encryption_enc_values_supported?: string[];
    /**
     * JSON array containing a list of Client Authentication methods supported by this Token Endpoint.
     */
    token_endpoint_auth_methods_supported?: string[];
    /**
     * JSON array containing a list of the JWS signing algorithms (alg values) supported by the Token Endpoint
     * for the signature on the JWT [JWT] used to authenticate the Client at the Token Endpoint for the
     * private_key_jwt and client_secret_jwt authentication methods.
     */
    token_endpoint_auth_signing_alg_values_supported?: string[];
    /**
     * JSON array containing a list of the display parameter values that the OpenID Provider supports.
     */
    display_values_supported?: string[];
    /**
     * JSON array containing a list of the Claim Types that the OpenID Provider supports.
     */
    claim_types_supported?: string[];
    /**
     * JSON array containing a list of the Claim Names of the Claims that
     * the OpenID Provider MAY be able to supply values for.
     */
    claims_supported: string[];
    /**
     * URL of a page containing human-readable information that developers
     * might want or need to know when using the OpenID Provider.
     */
    service_documentation?: string;
    /**
     * Languages and scripts supported for values in Claims being returned, represented as a JSON array
     * of BCP47 [RFC5646] language tag values. Not all languages and scripts are necessarily
     * supported for all Claim values.
     */
    claims_locales_supported?: string[];
    /**
     * Languages and scripts supported for the user interface,
     * represented as a JSON array of BCP47 [RFC5646] language tag values.
     */
    ui_locales_supported?: string[];
    /**
     *  Boolean value specifying whether the OP supports use of the claims parameter,
     * with true indicating support. If omitted, the default value is false.
     */
    claims_parameter_supported?: boolean;
    /**
     * Boolean value specifying whether the OP supports use of the request parameter,
     * with true indicating support. If omitted, the default value is false.
     */
    request_parameter_supported?: boolean;
    /**
     * Boolean value specifying whether the OP supports use of the request_uri parameter,
     * with true indicating support. If omitted, the default value is true.
     */
    request_uri_parameter_supported?: boolean;
    /**
     * Boolean value specifying whether the OP requires any request_uri values used to be
     * pre-registered using the request_uris registration parameter.
     */
    require_request_uri_registration?: boolean;
    /**
     * URL that the OpenID Provider provides to the person registering the Client
     * to read about the OP's requirements on how the Relying Party can use the data provided by the OP.
     */
    op_policy_uri?: string;
    /**
     * URL that the OpenID Provider provides to the person registering the Client
     * to read about OpenID Provider's terms of service.
     */
    op_tos_uri?: string;
    /**
     * URL of the authorization server's OAuth 2.0 revocation
     * endpoint.
     */
    revocation_endpoint?: string;
    /**
     * JSON array containing a list of client authentication
     * methods supported by this revocation endpoint.
     */
    revocation_endpoint_auth_methods_supported?: string[];
    /**
     * JSON array containing a list of the JWS signing
     * algorithms ("alg" values) supported by the revocation endpoint for
     * the signature on the JWT [JWT] used to authenticate the client at
     * the revocation endpoint for the "private_key_jwt" and
     * "client_secret_jwt" authentication methods.
     */
    revocation_endpoint_auth_signing_alg_values_supported?: string[];
    /**
     * URL of the authorization server's OAuth 2.0
     * introspection endpoint.
     */
    introspection_endpoint?: string;
    /**
     * JSON array containing a list of client authentication
     * methods supported by this introspection endpoint.
     */
    introspection_endpoint_auth_methods_supported?: string[];
    /**
     * JSON array containing a list of the JWS signing
     * algorithms ("alg" values) supported by the introspection endpoint
     * for the signature on the JWT [JWT] used to authenticate the client
     * at the introspection endpoint for the "private_key_jwt" and
     * "client_secret_jwt" authentication methods.
     */
    introspection_endpoint_auth_signing_alg_values_supported?: string[];
    /**
     * JSON array containing a list of Proof Key for Code
     * Exchange (PKCE) [RFC7636] code challenge methods supported by this
     * authorization server.
     */
    code_challenge_methods_supported?: string[];
    /**
     * URL of an OP iframe that supports cross-origin communications for session state information with the RP
     * Client, using the HTML5 postMessage API.
     */
    check_session_iframe: string;
    /**
     * URL at the OP to which an RP can perform a redirect to request that the End-User be logged out at the
     * OP.
     */
    end_session_endpoint: string;
    /**
     * Boolean value specifying whether the OP supports back-channel logout, with true indicating support.
     * If omitted, the default value is false.
     */
    backchannel_logout_supported?: boolean;
    /**
     * Boolean value specifying whether the OP can pass a sid (session ID) Claim in the Logout Token to
     * identify the RP session with the OP.
     */
    backchannel_logout_session_supported?: boolean;
}
