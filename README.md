# Asgardeo Auth JavaScript SDK

![Builder](https://github.com/asgardeo/asgardeo-auth-js-sdk/workflows/Builder/badge.svg)
[![Stackoverflow](https://img.shields.io/badge/Ask%20for%20help%20on-Stackoverflow-orange)](https://stackoverflow.com/questions/tagged/wso2is)
[![Join the chat at https://discord.gg/wso2](https://img.shields.io/badge/Join%20us%20on-Discord-%23e01563.svg)](https://discord.gg/wso2)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://github.com/wso2/product-is/blob/master/LICENSE)
[![Twitter](https://img.shields.io/twitter/follow/wso2.svg?style=social&label=Follow)](https://twitter.com/intent/follow?screen_name=wso2)

# ⚠️ *This is a core SDK that is not supposed to be used in applications.*

If you are looking for an SDK to use in your application, then you can find the relevant information in the table below:
| Framework/Library                                                 | Link                                                  |
|-------------------------------------------------------------------|-------------------------------------------------------|
| React                                                             | https://github.com/asgardeo/asgardeo-auth-react-sdk   |
| Vanilla JavaScript / jQuery / any other frontend frameworks/libraries | https://github.com/asgardeo/asgardeo-auth-spa-sdk |
| Node.js                                                           | https://github.com/asgardeo/asgardeo-auth-node-sdk    |
| Express.js                                                        | https://github.com/asgardeo/asgardeo-auth-express-sdk |
## Table of Content

-   [Introduction](#introduction)
-   [Install](#install)
-   [Getting Started](#getting-started)
    -   [Using an Embedded Script](#using-an-embedded-script)
    -   [Using a Module](#using-a-module)
-   [Browser Compatibility](#browser-compatibility)
-   [APIs](#apis)
    -   [constructor](#constructor)
    -   [initialize](#initialize)
    -   [getDataLayer](#getDataLayer)
    -   [getAuthorizationURLParams](#getAuthorizationURLParams)
    -   [getAuthorizationURL](#getAuthorizationURL)
    -   [requestAccessToken](#requestAccessToken)
    -   [getSignOutURL](#getSignOutURL)
    -   [getOIDCServiceEndpoints](#getOIDCServiceEndpoints)
    -   [getDecodedIDToken](#getDecodedIDToken)
    -   [getIDToken](#getIDToken)
    -   [getCryptoHelper](#getCryptoHelper)
    -   [getBasicUserInfo](#getBasicUserInfo)
    -   [revokeAccessToken](#revokeAccessToken)
    -   [refreshAccessToken](#refreshAccessToken)
    -   [getAccessToken](#getAccessToken)
    -   [requestCustomGrant](#requestCustomGrant)
    -   [isAuthenticated](#isAuthenticated)
    -   [getPKCECode](#getPKCECode)
    -   [setPKCECode](#setPKCECode)
    -   [isSignOutSuccessful](#isSignOutSuccessful)
    -   [didSignOutFail](#didSignOutFail)
    -   [updateConfig](#updateConfig)
-   [Data Storage](#data-storage)
    -   [Data Layer](#data-layer)
-   [CryptoUtils](#CryptoUtils)
-   [Models](#models)
    -   [AuthClientConfig\<T>](#AuthClientConfigT)
    -   [Store](#Store)
    -   [GetAuthURLConfig](#GetAuthURLConfig)
    -   [TokenResponse](#TokenResponse)
    -   [OIDCEndpoints](#OIDCEndpoints)
    -   [DecodedIDTokenPayload](#DecodedIDTokenPayload)
    -   [CustomGrantConfig](#CustomGrantConfig)
        -   [Custom Grant Template Tags](#Custom-Grant-Template-Tags)
    -   [SessionData](#SessionData)
    -   [OIDCProviderMetaData](#OIDCProviderMetaData)
    -   [TemporaryData](#TemporaryData)
    -   [BasicUserInfo](#BasicUserInfo)
    -   [JWKInterface](#JWKInterface)
-   [Develop](#develop)
    -   [Prerequisites](#prerequisites)
    -   [Installing Dependencies](#installing-dependencies)
-   [Error Codes](#error-codes)
-   [Contribute](#contribute)
-   [License](#license)

## Introduction

Asgardeo Auth JavaScript SDK provides the core methods that are needed to implement OIDC authentication in JavaScript/TypeScript-based apps. This SDK can be used to build SDKs for Single-Page Applications, React Native, Node.JS and various other frameworks that use JavaScript.

## Prerequisite

Create an organization in Asgardeo if you don't already have one. The organization name you choose will be referred to as `<org_name>` throughout this tutorial.

## Install

Install the library from the npm registry.

```
npm install @asgardeo/auth-js
```

## Getting Started

### Using an Embedded Script

```javascript
// The SDK provides a client that can be used to carry out the authentication.
import { AsgardeoAuthClient } from "@asgardeo/auth-js";

// Create a config object containing the necessary configurations.
const config = {
    signInRedirectURL: "http://localhost:3000/sign-in",
    signOutRedirectURL: "http://localhost:3000/dashboard",
    clientID: "client ID",
    baseUrl: "https://api.asgardeo.io/t/<org_name>"
};

// Create a Store class to store the authentication data. The following implementation uses the session storage.
class SessionStore {
    // Saves the data to the store.
    async setData(key, value) {
        sessionStorage.setItem(key, value);
    }

    // Gets the data from the store.
    async getData(key) {
        return sessionStorage.getItem(key);
    }

    // Removes the date from the store.
    async removeData(key) {
        sessionStorage.removeItem(key);
    }
}

class CryptoUtils {
    // Encodes the input data into base64 URL encoded string.
    public base64URLEncode(value) {
        return base64url.encode(value).replace(/\+/g, "-").replace(/\//g, "_").replace(/=/g, "");
    }

    // Decodes the base64 URL encoded string into the original data.
    public base64URLDecode(value) {
        return base64url.decode(value).toString();
    }

    // Hashes the input data using SHA256.
    public hashSha256(data) {
        return Buffer.from(sha256(new TextEncoder().encode(data)));
    }

    // Generates a random bytes of the specified length.
    public generateRandomBytes(length) {
        return randombytes(length);
    }

    // Verifies the JWT signature.
    public verifyJwt(
        idToken,
        jwk,
        algorithms,
        clientID,
        issuer,
        subject,
        clockTolerance
    ) {
        // Parses the key object into a format that would be accepted by verifyJwt()
        const key = parseJwk(jwk);

        return jwtVerify(idToken, jwk, {
            algorithms: algorithms,
            audience: clientID,
            clockTolerance: clockTolerance,
            issuer: issuer,
            subject: subject
        }).then(() => {
            return Promise.resolve(true);
        });
    }
}

// Instantiate the SessionStore class
const store = new SessionStore();

// Instantiate the CryptoUtils class
const cryptoUtils = new CryptoUtils();

// Instantiate the AsgardeoAuthClient and pass the store object as an argument into the constructor.
const auth = new AsgardeoAuthClient();

// Initialize the instance with the config object.
auth.initialize(config, store, cryptoUtils);

// To get the authorization URL, simply call this method.
auth.getAuthorizationURL()
    .then((url) => {
        // Redirect the user to the authentication URL. If this is used in a browser,
        // you may want to do something like this:
        window.location.href = url;
    })
    .catch((error) => {
        console.error(error);
    });

// Once you obtain the authentication code and the session state from the server, you can use this method
// to get the access token.
auth.requestAccessToken("code", "session-state", "state")
    .then((response) => {
        // Obtain the token and other related from the response;
        console.log(response);
    })
    .catch((error) => {
        console.error(error);
    });
```

[Learn more](#apis).

## APIs

The SDK provides a client class called `AsgardeoAuthClient` that provides you with the necessary methods to implement authentication.
You can instantiate the class and use the object to access the provided methods.

### constructor

```TypeScript
new AsgardeoAuthClient();
```

#### Description

This creates an instance of the `AsgardeoAuthClient` class and returns it.

#### Example

```TypeScript
const auth = new AsgardeoAuthClient();
```

---

### initialize

```TypeScript
initialize(config: AuthClientConfig<T>, store: Store, cryptoUtils: CryptoUtils): Promise<void>;
```

#### Arguments

1. config: [`AuthClientConfig<T>`](#AuthClientConfigT)

    This contains the configuration information needed to implement authentication such as the client ID, server origin etc. Additional configuration information that is needed to be stored can be passed by extending the type of this argument using the generic type parameter. For example, if you want the config to have an attribute called `foo`, you can create an interface called `Bar` in TypeScript and then pass that interface as the generic type to `AuthClientConfig` interface. To learn more about what attributes can be passed into this object, refer to the [`AuthClientConfig<T>`](#AuthClientConfigT) section.

    ```TypeScript
    interface Bar {
        foo: string
    }

    const auth = new AsgardeoAuthClient(config: AuthClientConfig<Bar>, store: Store, cryptoUtils: CryptoUtils);
    ```


2. store: [`Store`](#Store)

    This is the object of interface [`Store`](#Store) that is used by the SDK to store all the necessary data used ranging from the configuration data to the access token. You can implement the Store to create a class with your own implementation logic and pass an instance of the class as the second argument. This way, you will be able to get the data stored in your preferred place. To know more about implementing the [`Store`](#Store) interface, refer to the [Data Storage](#data-storage) section.

3. cryptoUtils: [`CryptoUtils`](#CryptoUtils)

    This is the object of the interface [`CryptoUtils`](#CryptoUtils) that is used by the SDK to perform cryptographic functions. Since the crypto implementation varies from environment to environment, this object is used to inject environment-specific crypto implementation. So, developers are expected to implement this interface and pass an object of this interface as an argument to the constructor. To know more about implementing this interface, refer to the [`CryptoUtils`](#CryptoUtils) section.

#### Description

This method initializes the instance with the config data.

#### Example

```TypeScript
const config = {
    signInRedirectURL: "http://localhost:3000/sign-in",
    signOutRedirectURL: "http://localhost:3000/dashboard",
    clientID: "client ID",
    baseUrl: "https://api.asgardeo.io/t/<org_name>"
};
const _store: Store = initiateStore(config.storage);
const _cryptoUtils: SPACryptoUtils = new SPACryptoUtils();

const auth = new AsgardeoAuthClient<MainThreadClientConfig>();

await auth.initialize(config, _store, _cryptoUtils);
```

---

### getDataLayer

```TypeScript
getDataLayer(): DataLayer<T>
```

#### Returns

dataLayer : [`DataLayer`](#data-layer)

A `DataLayer` object wraps the `Store` object passed during object instantiation and provides access to various types of data used by the SDK. To learn more about the various types of interfaces provide by the `DataLayer`, refer to the [Data layer](#data-layer) section.

#### Description

This method returns the `DataLayer` object used by the SDK to store authentication data.

#### Example

```TypeScript
const dataLayer = auth.getDataLayer();
```

---


### getCryptoHelper

```TypeScript
getCryptoHelper(): Promise<CryptoHelper>
```

#### Returns

cryptoHelper : [`CryptoHelper`](#CryptoUtils)

A `CryptoHelper` provides support for performing a cryptographic operation such as producing a PKCE code and verifying ID tokens. To learn more about the various types of interfaces provided by the `CryptoHelper`, refer to the [Crypto Utils](#CryptoUtils) section.

#### Description

This method returns the `CryptoHelper` object used by the SDK to perform cryptographic operations.

#### Example

```TypeScript
const cryptoHelper = auth.getCryptoHelper();
```
---

### getAuthorizationURLParams

```TypeScript
getAuthorizationURLParams(config?: GetAuthURLConfig, userID?: string): Promise<Map<string, string>>
```

#### Arguments

1. config: [`GetAuthURLConfig`](#GetAuthURLConfig) (optional)

    An optional config object that has the necessary attributes to configure this method. The `forceInit` attribute can be set to `true` to trigger a request to the `.well-known` endpoint and obtain the OIDC endpoints. By default, a request to the `.well-known` endpoint will be sent only if a request to it had not been sent before. If you wish to force a request to the endpoint, you can use this attribute.

    The object can only contain key-value pairs that you wish to append as path parameters to the authorization URL. For example, to set the `fidp` parameter, you can insert `fidp` as a key and its value to this object.

2. userID: `string` (optional)

    If you want to use the SDK to manage multiple user sessions, you can pass a unique ID here to generate an authorization URL specific to that user. This can be useful when this SDK is used in backend applications.

#### Returns

A Promise that resolves with the authorization URL Parameters.

#### Description

This method returns a Promise that resolves with the authorization URL Parameters, which then can be used to build the authorization request.

#### Example

```TypeScript
const config = {
    forceInit: true,
    fidp: "fb"
}

auth.getAuthorizationURLParams(config).then((params)=>{
    console.log(params);
}).catch((error)=>{
    console.error(error);
});
```

---

### getAuthorizationURL

```TypeScript
getAuthorizationURL(config?: GetAuthURLConfig, userID?: string): Promise<string>
```

#### Arguments

1. config: [`GetAuthURLConfig`](#GetAuthURLConfig) (optional)

    An optional config object that has the necessary attributes to configure this method. The `forceInit` attribute can be set to `true` to trigger a request to the `.well-known` endpoint and obtain the OIDC endpoints. By default, a request to the `.well-known` endpoint will be sent only if a request to it had not been sent before. If you wish to force a request to the endpoint, you can use this attribute.

    The object can only contain key-value pairs that you wish to append as path parameters to the authorization URL. For example, to set the `fidp` parameter, you can insert `fidp` as a key and its value to this object.

2. userID: `string` (optional)

    If you want to use the SDK to manage multiple user sessions, you can pass a unique ID here to generate an authorization URL specific to that user. This can be useful when this SDK is used in backend applications.

#### Returns

A Promise that resolves with the authorization URL

#### Description

This method returns a Promise that resolves with the authorization URL. The user can be redirected to this URL to authenticate themselves and authorize the client.

#### Example

```TypeScript
const config = {
    forceInit: true,
    fidp: "fb"
}

auth.getAuthorizationURL(config).then((url)=>{
    window.location.href = url;
}).catch((error)=>{
    console.error(error);
});
```

---

### requestAccessToken

```TypeScript
requestAccessToken(authorizationCode: string, sessionState: string, state: string, userID?: string, tokenRequestConfig: { params: Record<string, unknown> }): Promise<TokenResponse>
```

#### Arguments

1. authorizationCode: `string`

    This is the authorization code obtained from Asgardeo after a user signs in.

2. sessionState: `string`

    This is the session state obtained from Asgardeo after a user signs in.

3. state: `string`
   This is the the state parameter passed in the authorization URL.

4. userID: `string` (optional)

    If you want to use the SDK to manage multiple user sessions, you can pass a unique ID here to request an access token specific to that user. This can be useful when this SDK is used in backend applications.

5. tokenRequestConfig: `object` (optional)

    An optional configuration object that allows you to augment the token request.

    - `params` (Mandatory): Key-value pairs to be sent as additional parameters in the token request payload.


       ```TypeScript
       tokenRequestConfig: {
           params: Record<string, unknown>
       }
       ```
#### Returns

A Promise that resolves with the [`TokenResponse`](#TokenResponse) object.

The object contains data returned by the token response such as the access token, id token, refresh token, etc. You can learn more about the data returned from the [`TokenResponse`](#TokenResponse) section.

#### Description

This method uses the authorization code and the session state that are passed as arguments to send a request to the `token` endpoint to obtain the access token and the id token. The sign-in functionality can be implemented by calling the [`getAuthorizationURL`](#getAuthorizationURL) method followed by this method.

#### Example

```TypeScript
auth.requestAccessToken("auth-code", "session-state", "request_0").then((tokenResponse)=>{
    console.log(tokenResponse);
}).catch((error)=>{
    console.error(error);
});
```

---

### getSignOutURL

```TypeScript
getSignOutURL(userID?: string): Promise<string>
```

#### Argument

1. userID: `string` (optional)

    If you want to use the SDK to manage multiple user sessions, you can pass a unique ID here. This can be useful when this SDK is used in backend applications.

#### Returns

signOutURL: `Promise<string>`

The user should be redirected to this URL in order to sign out of the server.

#### Description

This method returns the sign-out URL to which the user should be redirected to be signed out from the server.

#### Example

```TypeScript
// This should be within an async function.
const signOutURL = await auth.getSignOutURL();
```

---

### getOIDCServiceEndpoints

```TypeScript
getOIDCServiceEndpoints(): Promise<OIDCEndpoints>
```

#### Returns

oidcEndpoints: `Promise<[OIDCEndpoints](#OIDCEndpoints)>`

An object containing the OIDC service endpoints returned by the `.well-known` endpoint.

#### Description

This method returns the OIDC service endpoints obtained from the `.well-known` endpoint. To learn more about what endpoints are returned, checkout the [`OIDCEndpoints`](#OIDCEndpoints) section.

#### Example

```TypeScript
// This should be within an async function.
const oidcEndpoints = await auth.getOIDCServiceEndpoints();
```

---

### getDecodedIDToken

```TypeScript
getDecodedIDToken(userID?: string): Promise<DecodedIDTokenPayload>
```

#### Argument

1. userID: `string` (optional)

    If you want to use the SDK to manage multiple user sessions, you can pass a unique ID here. This can be useful when this SDK is used in backend applications.

#### Returns

decodedIDTokenPayload: `Promise<[DecodedIDTokenPayload](#DecodedIDTokenPayload)>`
The decoded ID token payload.

#### Description

This method decodes the payload of the id token and returns the decoded values.

#### Example

```TypeScript
const decodedIDTokenPayload = await auth.getDecodedIDToken();
```

---

### getIDToken

```TypeScript
getIDToken(userID?: string): Promise<string>
```

#### Argument

1. userID: `string` (optional)

    If you want to use the SDK to manage multiple user sessions, you can pass a unique ID here. This can be useful when this SDK is used in backend applications.

#### Returns

idToken: `Promise<string>`
The id token.

#### Description

This method returns the id token.

#### Example

```TypeScript
const idToken = await auth.getIDToken();
```

---

### getBasicUserInfo

```TypeScript
getBasicUserInfo(userID?: string): Promise<BasicUserInfo>
```

#### Argument

1. userID: `string` (optional)

    If you want to use the SDK to manage multiple user sessions, you can pass a unique ID here. This can be useful when this SDK is used in backend applications.

#### Returns

basicUserInfo: `Promise<[BasicUserInfo](#BasicUserInfo)>`
An object containing basic user information obtained from the id token.

#### Description

This method returns the basic user information obtained from the payload. To learn more about what information is returned, checkout the [`DecodedIDTokenPayload`](#DecodedIDTokenPayload) model.

#### Example

```TypeScript
// This should be used within an async function.
const basicUserInfo = await auth.getBasicUserInfo();
```

---

### revokeAccessToken

```TypeScript
revokeAccessToken(userID?: string): Promise<AxiosResponse>
```

#### Argument

1. userID: `string` (optional)

    If you want to use the SDK to manage multiple user sessions, you can pass a unique ID here. This can be useful when this SDK is used in backend applications.

#### Returns

A Promise that resolves with the response returned by the server.

#### Description

This method clears the authentication data and sends a request to revoke the access token. You can use this method if you want to sign the user out of your application but not from the server.

#### Example

```TypeScript
auth.revokeAccessToken().then((response)=>{
    console.log(response);
}).catch((error)=>{
    console.error(error);
})
```

---

### refreshAccessToken

```TypeScript
refreshAccessToken(userID?: string): Promise<TokenResponse>
```

#### Argument

1. userID: `string` (optional)

    If you want to use the SDK to manage multiple user sessions, you can pass a unique ID here. This can be useful when this SDK is used in backend applications.

#### Returns

A Promise that resolves with the token response that contains the token information.

#### Description

This method sends a refresh-token request and returns a promise that resolves with the token information. To learn more about what information is returned, checkout the [`TokenResponse`](#TokenResponse) model. The existing authentication data in the store is automatically updated with the new information returned by this request.

#### Example

```TypeScript
auth.refreshAccessToken().then((response)=>{
    console.log(response);
}).catch((error)=>{
    console.error(error);
})
```

---

### getAccessToken

```TypeScript
getAccessToken(userID?: string): Promise<string>
```

#### Argument

1. userID: `string` (optional)

    If you want to use the SDK to manage multiple user sessions, you can pass a unique ID here. This can be useful when this SDK is used in backend applications.

#### Returns

accessToken: `string`
The access token.

#### Description

This method returns the access token stored in the store. If you want to send a request to obtain the access token from the server, use the [`requestAccessToken`](#requestAccessToken) method.

#### Example

```TypeScript
// This should be used within an async function.
const accessToken = await auth.getAccessToken();
```

---

### requestCustomGrant

```TypeScript
requestCustomGrant(config: CustomGrantConfig, userID?: string): Promise<TokenResponse | AxiosResponse>
```

#### Arguments

1. config: [`CustomGrantConfig`](#CustomGrantConfig)
   The config object contains attributes that would be used to configure the custom grant request. To learn more about the different configurations available, checkout the [`CustomGrantConfig`](#CustomGrantConfig) model.
2. userID: `string` (optional)

    If you want to use the SDK to manage multiple user sessions, you can pass a unique ID here. This can be useful when this SDK is used in backend applications.

#### Returns

A Promise that resolves with the token information or the response returned by the server depending on the configuration passed.

#### Description

This method can be used to send custom-grant requests to Asgardeo.

#### Example

```TypeScript
    const config = {
      attachToken: false,
      data: {
          client_id: "{{clientID}}",
          grant_type: "account_switch",
          scope: "{{scope}}",
          token: "{{token}}",
      },
      id: "account-switch",
      returnResponse: true,
      returnsSession: true,
      signInRequired: true
    }

    auth.requestCustomGrant(config).then((response)=>{
        console.log(response);
    }).catch((error)=>{
        console.error(error);
    });
```

---

### isAuthenticated

```TypeScript
isAuthenticated(userID?: string): Promise<boolean>
```

#### Argument

1. userID: `string` (optional)

    If you want to use the SDK to manage multiple user sessions, you can pass a unique ID here. This can be useful when this SDK is used in backend applications.

#### Returns

isAuth: `boolean`
A boolean value that indicates of the user is authenticated or not.

#### Description

This method returns a boolean value indicating if the user is authenticated or not.

#### Example

```TypeScript
// This should be within an async function.
const isAuth = await auth.isAuthenticated();
```

---

### getPKCECode

```TypeScript
getPKCECode(state: string, userID?: string): string
```

#### Argument

1. state: `string`
   The state parameter that was passed in the authorization request.

2. userID: `string` (optional)

    If you want to use the SDK to manage multiple user sessions, you can pass a unique ID here. This can be useful when this SDK is used in backend applications.

#### Returns

pkce: `string`

The PKCE code

#### Description

This code returns the PKCE code generated when the authorization URL is generated by the [`getAuthorizationURL`](#getAuthorizationURL) method.

#### Example

```TypeScript
const pkce = auth.getPKCECode(state);
```

---

### setPKCECode

```TypeScript
setPKCECode(pkce: string, state: string, userID?: string): void
```

#### Arguments

1. pkce: `string`

The PKCE code generated by the [`getAuthorizationURL`](#getAuthorizationURL) method. 2. state: `string`
The state parameter that was passed in the authorization request. 3. userID: `string` (optional)

    If you want to use the SDK to manage multiple user sessions, you can pass a unique ID here. This can be useful when this SDK is used in backend applications.

#### Description

This method sets the PKCE code to the store. The PKCE code is usually stored in the store by the SDK. But there could be instances when the store could be cleared such as when the data is stored in the memory and the user is redirected to the authorization endpoint in a Single Page Application. When the user is redirected back to the app, the authorization code, session state, and the PKCE code will have to be sent to the server to obtain the access token. However, since, during redirection, everything in the memory is cleared, the PKCE code cannot be obtained. In such instances, the [`getPKCECode`](#getPKCECode) method can be used to get the PKCE code before redirection and store it in a place from where it can be retrieved after redirection, and then this method can be used to save the PKCE code to the store so that the [`requestAccessToken`](#requestAccessToken) method can run successfully.

#### Example

```TypeScript
auth.setPKCECode(pkce, state);
```

---

### isSignOutSuccessful

```TypeScript
static isSignOutSuccessful(signOutRedirectURL: string): boolean
```

**This is a static method.**

#### Arguments

1. signOutRedirectURL: `string`

    The URL to which the user is redirected to after signing out from the server.

#### Returns

isSignedOut: `boolean`

A boolean value indicating if the user has been signed out or not.

#### Description

This method returns if the user has been successfully signed out or not. When a user signs out from the server, the user is redirected to the URL specified by the `signOutRedirectURL` in the config object passed into the constructor of the `AsgardeoAuthClient`. The server appends path parameters indicating if the sign-out is successful. This method reads the URL and returns if the sign-out is successful or not. So, make sure you pass as the argument the URL to which the user has been redirected to after signing out from the server.

#### Example

```TypeScript
const isSignedOut = auth.isSignOutSuccessful(window.location.href);
```

---

### didSignOutFail

```TypeScript
static didSignOutFail(signOutRedirectURL: string): boolean
```

**This is a static method.**

#### Arguments

1. signOutRedirectURL: `string`

    The URL to which the user is redirected to after signing out from the server.

#### Returns

didSignOutFail: `boolean`

A boolean value indicating if sign-out failed or not.

#### Description

This method returns if sign-out failed or not. When a user signs out from the server, the user is redirected to the URL specified by the `signOutRedirectURL` in the config object passed into the constructor of the `AsgardeoAuthClient`. The server appends path parameters indicating if the sign-out is successful. This method reads the URL and returns if the sign-out failed or not. So, make sure you pass as the argument the URL to which the user has been redirected to after signing out from the server.

#### Example

```TypeScript
const didSignOutFail = auth.didSignOutFail(window.location.href);
```

---

### updateConfig

```TypeScript
updateConfig(config: Partial<AuthClientConfig<T>>): Promise<void>
```

#### Arguments

1. config: [`AuthClientConfig<T>`](#AuthClientConfigT)

The config object containing the attributes that can be used to configure the SDK. To learn more about the available attributes, refer to the [`AuthClientConfig>T>`](#AuthClientConfigT) model.

#### Description

This method can be used to update the configurations passed into the constructor of the `AsgardeoAuthClient`. Please note that every attribute in the config object passed as the argument here is optional. Use this method if you want to update certain attributes after instantiating the class.

#### Example

```TypeScript
// This should be within an async function.
await auth.updateConfig({
    signOutRedirectURL: "http://localhost:3000/sign-out"
});
```

## Data Storage

Since the SDK was developed with the view of being able to support various platforms such as mobile apps, browsers and node.js servers, the SDK allows developers to use their preferred mode of storage. To that end, the SDK allows you to pass a store object when instantiating the `AsgardeoAuthClient`. This store object contains methods that can be used to store, retrieve and delete data. The SDK provides a Store interface that you can implement to create your own Store class. You can refer to the [`Store`](#store) section to learn more about the `Store` interface.

There are three methods that are to be implemented by the developer. They are

1. `setData`
2. `getData`
3. `removeData`

The `setData` method is used to store data. The `getData` method is used to retrieve data. The `removeData` method is used to delete data. The SDK converts the data to be stored into a JSON string internally and then calls the `setData` method to store the data. The data is represented as a key-value pairs in the SDK. The SDK uses four keys internally and you can learn about them by referring to the [Data Layer](#data-layer) section. So, every JSON stringified data value is supposed to be stored against the passed key in the data store. A sample implementation of the `Store` class using the browser session storage is given here.

```TypeScript
class SessionStore implements Store {
    public setData(key: string, value: string): void {
        sessionStorage.setItem(key, value);
    }

    public getData(key: string): string {
        return sessionStorage.getItem(key);
    }

    public removeData(key: string): void {
        sessionStorage.removeItem(key);
    }
}
```

### Data Layer

The data layer is implemented within the SDK encapsulating the `Store` object passed into the constructor. The data layer acts as the interface between the SDK and the store object and provides a more developer-friendly interface to store, retrieve and delete data. Four keys are used to store four different sets of data. The keys are:

1. Session Data
   Stores session data such as the access token, id token, refresh token, session state etc. Refer to [`SessionData`](#SessionData) to get the full list of data stored.
2. OIDC Provider Meta Data
   Stores regarding OIDC Meta Data obtained from the `.well-known` endpoint. Refer to [`OIDCProviderMetaData`](#OIDCProviderMetaData) for the full list of data stored.
3. Config Data
   Stores the config data passed to the constructor. Refer to [`AuthClientConfig<T>`](#AuthClientConfigT) for the full list of data stored.
4. Temporary Data
   Stores data that is temporary. In most cases, you wouldn't need this.

All these four keys get methods to set, get and remove data as whole. In addition to this, all these keys get methods to set, get, and remove specific data referred to by their respective keys. The following table describes the methods provided by the data layer.
| Method                              | Arguments                                                                                      | Returns                                                      | Description                                                                     |
|-------------------------------------|------------------------------------------------------------------------------------------------|--------------------------------------------------------------|---------------------------------------------------------------------------------|
| setSessionData                      | sessionData: [`SessionData`](#SessionData)                                                     | `Promise<void>`                                              | Saves session data in bulk.                                                     |
| setOIDCProviderMetaData             | oidcProviderMetaData: [`OIDCProviderMetaData`](#OIDCProviderMetaData)                          | `Promise<void>`                                              | Saves OIDC Provider Meta data in bulk.                                          |
| setConfigData                       | config: [`AuthClientConfig<T>`](#AuthClientConfigT)                                            | `Promise<void>`                                              | Saves config data in bulk.                                                      |
| setTemporaryData                    | data: [`TemporaryData`](#TemporaryData)                                                        | `Promise<void>`                                              | Saves temporary data in bulk.                                                   |
| getSessionData                      |                                                                                                | `Promise<`[`SessionData`](#SessionData)`>`                   | Retrieves session data in bulk.                                                 |
| getOIDCProviderMetaData             |                                                                                                | `Promise<`[`OIDCProviderMetaData`](#OIDCProviderMetaData)`>` | Retrieves OIDC Provider Meta data in bulk.                                      |
| getConfigData                       |                                                                                                | `Promise<`[`AuthClientConfig<T>`](#`AuthClientConfig<T>`)`>` | Retrieves config data in bulk.                                                  |
| getTemporaryData                    |                                                                                                | `Promise<`{ [key: `string`]: [StoreValue](#StoreValue)}`>`   | Retrieves temporary data in bulk.                                               |
| removeSessionData                   |                                                                                                | `Promise<void>`                                              | Removes session data in bulk.                                                   |
| removeOIDCProviderMetaData          |                                                                                                | `Promise<void>`                                              | Removes OIDC Provider Meta data in bulk.                                        |
| removeConfigData                    |                                                                                                | `Promise<void>`                                              | Removes config data in bulk.                                                    |
| removeTemporaryData                 |                                                                                                | `Promise<void>`                                              | Removes temporary data in bulk.                                                 |
| setSessionDataParameter             | key: keyof [`SessionData`](#SessionData), value: [`StoreValue`](#StoreValue)                   | `Promise<void>`                                              | Saves the passed data against the specified key in the session data.            |
| setOIDCProviderMetaDataParameter    | key: keyof [`OIDCProviderMetaData`](#OIDCProviderMetaData), value: [`StoreValue`](#StoreValue) | `Promise<void>`                                              | Saves the passed data against the specified key in the OIDC Provider Meta data. |
| setConfigDataParameter              | key: keyof [`AuthClientConfig<T>`](#AuthClientConfigT), value: [`StoreValue`](#`StoreValue`)   | `Promise<void>`                                              | Saves the passed data against the specified key in the config data.             |
| setTemporaryDataParameter           | key: `string`, value: [`StoreValue`](#`StoreValue`)                                            | `Promise<void>`                                              | Saves the passed data against the specified key in the temporary data.          |
| getSessionDataParameter             | key: keyof [`SessionData`](#SessionData)                                                       | `Promise<`[`StoreValue`](#StoreValue)`>`                     | Retrieves the data for the specified key from the session data.                 |
| getOIDCProviderMetaDataParameter    | key: keyof [`OIDCProviderMetaData`](#OIDCProviderMetaData)                                     | `Promise<`[`StoreValue`](#StoreValue)`>`                     | Retrieves the data for the specified key from the OIDC Provider Meta data.      |
| getConfigDataParameter              | key: keyof [`AuthClientConfig<T>`](#AuthClientConfigT)                                         | `Promise<`[`StoreValue`](#StoreValue)`>`                     | Retrieves the data for the specified key from the config data.                  |
| getTemporaryDataParameter           | key: `string`                                                                                  | `Promise<`[`StoreValue`](#StoreValue)`>`                     | Retrieves the data for the specified key from the temporary data.               |
| removeSessionDataParameter          | key: keyof [`SessionData`](#SessionData)                                                       | `Promise<void>`                                              | Removes the data with the specified key from the session data.                  |
| removeOIDCProviderMetaDataParameter | key: keyof [`OIDCProviderMetaData`](#OIDCProviderMetaData)                                     | `Promise<void>`                                              | Removes the data with the specified key from the OIDC Provider Meta data.       |
| removeConfigDataParameter           | key: keyof [`AuthClientConfig<T>`](#AuthClientConfigT)                                         | `Promise<void>`                                              | Removes the data with the specified key from the config data.                   |
| removeTemporaryDataParameter        | key: `string`                                                                                  | `Promise<void>`                                              | Removes the data with the specified key from the temporary data.                |

## CryptoUtils

The CryptoUtils interface defines the methods required to perform cryptographic operations such as producing a PKCE code and verifying ID tokens. The following table describes the methods provided by the CryptoUtils interface.
| Method                | Arguments                          | Returns            | Description                                                      |
|-----------------------|------------------------------------|--------------------|------------------------------------------------------------------|
| `base64urlEncode`     | input: `T`                         | `string`           | Encodes the passed input string to a base64url encoded string.   |
| `base64urlDecode`     | input: `string`                    | `string`           | Decodes the passed input string from a base64url encoded string. |
| `hashSha256`          | input: `string`                    | `T`                | Hashes the passed input string using SHA-256.                    |
| `generateRandomBytes` | length: `number`                   | `T`                | Generates random bytes of the specified length.                  |
| `verifyJwt`           | jwt: `string`, jwk: `JWKInterface` | `Promise<boolean>` | Verifies the passed JWT using the passed JWK.                    |

**NOTE: The return type of the `hashSha256` and `generateRandomBytes` method should be the same as the type of the argument of the `base64urlEncode` method.**

These methods should be implemented in a class and the instance of the class should be passed as an argument into the constructor of `AsgardeoAuthClient`.

## Models

### AuthClientConfig\<T>

This model has the following attributes.
|Attribute| Required/Optional| Type | Default Value| Description|
|--|--|--|--|--|
|`signInRedirectURL` |Required|`string`|""|The URL to redirect to after the user authorizes the client app. eg: `https//localhost:3000/sign-in`|
|`signOutRedirectURL` |Optional|`string`| The `signInRedirectURL` URL will be used if this value is not provided. |The URL to redirect to after the user |signs out. eg: `http://localhost:3000/dashboard`|
|`clientHost`|Optional| `string`|The origin of the client app obtained using `window.origin`|The hostname of the client app. eg: `https://localhost:3000`|
|`clientID`|Required| `string`|""|The client ID of the OIDC application hosted in the Asgardeo.|
|`clientSecret`|Optional| `string`|""|The client secret of the OIDC application|
|`enablePKCE`|Optional| `boolean`|`true`| Specifies if a PKCE should be sent with the request for the authorization code.|
|`prompt`|Optional| `string`|""|Specifies the prompt type of an OIDC request|
|`responseMode`|Optional| `ResponseMode`|`"query"`|Specifies the response mode. The value can either be `query` or `form_post`|
|`scope`|Optional| `string[]`|`["openid"]`|Specifies the requested scopes.|
|`baseUrl`|Required (If `wellKnownEndpoint` or `endpoints` is not provided)| `string`|""|The origin of the Identity Provider. eg: https://api.asgardeo.io/t/<org_name>.|
|`endpoints`|Optional (Required to provide all endpoints, if `wellKnownEndpoint` or `baseUrl` is not provided)| `OIDCEndpoints`|[OIDC Endpoints Default Values](#oidc-endpoints)|The OIDC endpoint URLs. The SDK will try to obtain the endpoint URLS |using the `.well-known` endpoint. If this fails, the SDK will use these endpoint URLs. If this attribute is not set, then the default endpoint URLs will be |used.
|`wellKnownEndpoint`|Optional (Required if `baseUrl` or `endpoints` is not provided)| `string`|`"/oauth2/token/.well-known/openid-configuration"`| The URL of the `.well-known` endpoint.|
|`validateIDToken`|Optional| `boolean`|`true`|Allows you to enable/disable JWT ID token validation after obtaining the ID token.|
|`validateIDTokenIssuer`(optional) | `boolean` | `true` | Allows you to enable/disable JWT ID token issuer validation after obtaining the ID token (This config is applicable only when JWT ID token validation is enabled). |
|`clockTolerance`|Optional| `number`|`60`|Allows you to configure the leeway when validating the id_token.|
|`sendCookiesInRequests`|Optional| `boolean`|`true`|Specifies if cookies should be sent in the requests.|
|`sendIdTokenInLogoutRequest`|Optional| `boolean`|`false`|Specifies if `id_token_hint` parameter should be sent in the logout request instead of the default `client_id` parameter.|

The `AuthClientConfig<T>` can be extended by passing an interface as the generic type. For example, if you want to add an attribute called `foo` to the config object, you can create an interface called `Bar` and pass that as the generic type into the `AuthClientConfig<T>` interface.

```TypeScript
interface Bar {
    foo: string
}

const config: AuthClientConfig<Bar> ={
    ...
}
```

### Store

| Method       | Required/Optional | Arguments                      | Returns                                                                                                                                                                         | Description                                                                                                                         |
|--------------|-------------------|--------------------------------|---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|-------------------------------------------------------------------------------------------------------------------------------------|
| `setData`    | Required          | key: `string`, value: `string` | `Promise<void>`                                                                                                                                                                 | This method saves the passed value to the store. The data to be saved is JSON stringified so will be passed by the SDK as a string. |
| `getData`    | Required          | key: `string`\|`string`        | This method retrieves the data from the store and returns a Promise that resolves with it. Since the SDK stores the data as a JSON string, the returned value will be a string. |                                                                                                                                     |
| `removeData` | Required          | key: `string`                  | `Promise<void>`                                                                                                                                                                 | Removes the data with the specified key from the store.                                                                             |

### GetAuthURLConfig

| Method        | Required/Optional | Type                  | Default Value | Description                                                                                                                                                            |
|---------------|-------------------|-----------------------|---------------|------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `fidp`        | Optional          | `string`              | ""            | The `fidp` parameter that can be used to redirect a user directly to an IdP's sign-in page.                                                                            |
| `forceInit`   | Optional          | `boolean`             | `false`       | Forces obtaining the OIDC endpoints from the `.well-known` endpoint. A request to this endpoint is not sent if a request has already been sent. This forces a request. |
| key: `string` | Optional          | `string` \| `boolean` | ""            | Any key-value pair to be appended as path parameters to the authorization URL.                                                                                         |

### TokenResponse

| Method         | Type     | Description                 |
|----------------|----------|-----------------------------|
| `accessToken`  | `string` | The access token.           |
| `idToken`      | `string` | The id token.               |
| `expiresIn`    | `string` | The expiry time in seconds. |
| `scope`        | `string` | The scope of the token.     |
| `refreshToken` | `string` | The refresh token.          |
| `tokenType`    | `string` | The token type.             |

### OIDCEndpoints

| Method                  | Type     | Default Value                                      | Description                                                               |
|-------------------------|----------|----------------------------------------------------|---------------------------------------------------------------------------|
| `authorizationEndpoint` | `string` | `"/oauth2/authorize"`                              | The authorization endpoint.                                               |
| `tokenEndpoint`         | `string` | `"/oauth2/token"`                                  | The token endpoint.                                                       |
| `userinfoEndpoint`      | `string` | ""                                                 | The user-info endpoint.                                                   |
| `jwksUri`               | `string` | `"/oauth2/jwks"`                                   | The JWKS URI.                                                             |
| `registrationEndpoint`  | `string` | ""                                                 | The registration endpoint.                                                |
| `revocationEndpoint`    | `string` | `"/oauth2/revoke"`                                 | The token-revocation endpoint.                                            |
| `introspectionEndpoint` | `string` | ""                                                 | The introspection endpoint.                                               |
| `checkSessionIframe`    | `string` | `"/oidc/checksession"`                             | The check-session endpoint.                                               |
| `endSessionEndpoint`    | `string` | `"/oidc/logout"`                                   | The end-session endpoint.                                                 |
| `issuer`                | `string` | ""                                                 | The issuer of the token.

### DecodedIDTokenPayload

| Method             | Type                   | Description                                    |
|--------------------|------------------------|------------------------------------------------|
| aud                | `string` \| `string[]` | The audience.                                  |
| sub                | `string`               | The subject. This is the username of the user. |
| iss                | `string`               | The token issuer.                              |
| email              | `string`               | The email address.                             |
| preferred_username | `string`               | The preferred username.                        |
| tenant_domain      | `string`               | The tenant domain to which the user belongs.   |

### CustomGrantConfig

| Attribute        | Required/Optional | Type      | Default Value | Description                                                                                                                                                                                                                   |
|------------------|-------------------|-----------|---------------|-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `id`             | Required          | `string`  | ""            | Every custom-grant request should have an id. This attributes takes that id.                                                                                                                                                  |
| `data`           | Required          | `any`     | `null`        | The data that should be sent in the body of the custom-grant request. You can use template tags to send session information. Refer to the [Custom Grant Template Tags](#custom-grant-template-tags) section for more details. |
| `signInRequired` | Required          | `boolean` | `false`       | Specifies if the user should be sign-in or not to dispatch this custom-grant request.                                                                                                                                         |
| `attachToken`    | Required          | `boolean` | `false`       | Specifies if the access token should be attached to the header of the request. <br/><br/> 💡 **Note** : If the request is credentialed,  server must specify a domain, and cannot use wild carding. This would lead to [CORS errors](https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS) and if you intend to bypass this behavior per request, add `wihCredentials: false` to the `httpRequest` config.                                                                                                                                            |
| `returnsSession` | Required          | `boolean` | `false`       | Specifies if the the request returns session information such as the access token.                                                                                                                                            |
| `tokenEndpoint`  | Optional          | `string`  | `null`        | Token endpoint is an optional parameter which can be used to provide an optional token endpoint that will be used instead of default token endpoint.                                                                          |

#### Custom Grant Template Tags

Session information can be attached to the body of a custom-grant request using template tags. This is useful when the session information is not exposed outside the SDK but you want such information to be used in custom-grant requests. The following table lists the available template tags.
| Tag                | Data               |
|--------------------|--------------------|
| "{{token}}"        | The access token.  |
| {{username}}"      | The username.      |
| "{{scope}}"        | The scope.         |
| {{clientID}}"      | The client ID.     |
| "{{clientSecret}}" | The client secret. |

### SessionData

| Attribute       | Type     | description                                      |
|-----------------|----------|--------------------------------------------------|
| `access_token`  | `string` | The access token.                                |
| `id_token`      | `string` | The id token.                                    |
| `expires_in`    | `string` | The expiry time.                                 |
| `scope`         | `string` | The scope.                                       |
| `refresh_token` | `string` | The refresh token.                               |
| `token_type`    | `string` | The token type.                                  |
| `session_state` | `string` | The session state obtained after authentication. |
| `created_at`    | `number` | The time when the session was created.           |

### OIDCProviderMetaData

| Attribute                                                  | Type       | description                                                                                                                                                                                                                                                                                  |
|------------------------------------------------------------|------------|----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `issuer`                                                   | `string`   | URL using the https scheme with no query or fragment component that the OP asserts as its Issuer Identifier.                                                                                                                                                                                 |
| `authorization_endpoint`                                   | `string`   | URL of the OP's OAuth 2.0 Authorization Endpoint.                                                                                                                                                                                                                                            |
| `token_endpoint`                                           | `string`   | URL of the OP's OAuth 2.0 Token Endpoint.                                                                                                                                                                                                                                                    |
| `userinfo_endpoint`                                        | `string`   | URL of the OP's UserInfo Endpoint.                                                                                                                                                                                                                                                           |
| `jwks_uri`                                                 | `string`   | URL of the OP's JSON Web Key Set [JWK] document. This contains the signing key(s) the RP uses to validate signatures from the OP.                                                                                                                                                            |
| `registration_endpoint`                                    | `string`   | URL of the OP's Dynamic Client Registration Endpoint                                                                                                                                                                                                                                         |
| `scopes_supported`                                         | `string[]` | JSON array containing a list of the OAuth 2.0 [RFC6749] scope values that this server supports.                                                                                                                                                                                              |
| `response_types_supported`                                 | `string[]` | JSON array containing a list of the OAuth 2.0 response_type values that this OP supports.                                                                                                                                                                                                    |
| `response_modes_supported`                                 | `string[]` | JSON array containing a list of the OAuth 2.0 response_mode values that this OP supports.                                                                                                                                                                                                    |
| `grant_types_supported`                                    | `string[]` | JSON array containing a list of the OAuth 2.0 Grant Type values that this OP supports.                                                                                                                                                                                                       |
| `acr_values_supported`                                     | `string[]` | JSON array containing a list of the Authentication Context Class References that this OP supports.                                                                                                                                                                                           |
| `subject_types_supported`                                  | `string[]` | JSON array containing a list of the Subject Identifier types that this OP supports.                                                                                                                                                                                                          |
| `id_token_signing_alg_values_supported`                    | `string[]` | JSON array containing a list of the JWS signing algorithms(alg values) supported by the OP for the ID Token to encode the Claims in a JWT [JWT].                                                                                                                                             |
| `id_token_encryption_alg_values_supported`                 | `string[]` | JSON array containing a list of the JWE encryption algorithms (alg values) supported by the OP for the ID Token to encode the Claims in a JWT [JWT].                                                                                                                                         |
| `id_token_encryption_enc_values_supported`                 | `string[]` | JSON array containing a list of the JWE encryption algorithms (enc values) supported by the OP for the ID Token to encode the Claims in a JWT [JWT].                                                                                                                                         |
| `userinfo_signing_alg_values_supported`                    | `string[]` | JSON array containing a list of the JWS [JWS] signing algorithms (alg values) [JWA] supported by the UserInfo Endpoint to encode the Claims in a JWT [JWT].                                                                                                                                  |
| `userinfo_encryption_alg_values_supported`                 | `string[]` | JSON array containing a list of the JWE [JWE] encryption algorithms (alg values) [JWA] supported by the UserInfo Endpoint to encode the Claims in a JWT [JWT].                                                                                                                               |
| `userinfo_encryption_enc_values_supported`                 | `string[]` | JSON array containing a list of the JWE encryption algorithms (enc values) [JWA] supported by the UserInfo Endpoint to encode the Claims in a JWT [JWT]                                                                                                                                      |
| `request_object_signing_alg_values_supported`              | `string[]` | JSON array containing a list of the JWS signing algorithms (alg values) supported by the OP for Request Objects                                                                                                                                                                              |
| `request_object_encryption_alg_values_supported`           | `string[]` | JSON array containing a list of the JWE encryption algorithms (alg values) supported by the OP for Request Objects.                                                                                                                                                                          |
| `request_object_encryption_enc_values_supported`           | `string[]` | JSON array containing a list of the JWE encryption algorithms (enc values) supported by the OP for Request Objects.                                                                                                                                                                          |
| `token_endpoint_auth_methods_supported`                    | `string[]` | JSON array containing a list of Client Authentication methods supported by this Token Endpoint.                                                                                                                                                                                              |
| `token_endpoint_auth_signing_alg_values_supported`         | `string[]` | JSON array containing a list of the JWS signing algorithms (alg values) supported by the Token Endpoint for the signature on the JWT [JWT] used to authenticate the Client at the Token Endpoint for the private_key_jwt and client_secret_jwt authentication methods.                       |
| `display_values_supported`                                 | `string[]` | JSON array containing a list of the display parameter values that the OpenID Provider supports.                                                                                                                                                                                              |
| `claim_types_supported`                                    | `string[]` | JSON array containing a list of the Claim Types that the OpenID Provider supports.                                                                                                                                                                                                           |
| `claims_supported`                                         | `string[]` | JSON array containing a list of the Claim Names of the Claims that the OpenID Provider MAY be able to supply values for.                                                                                                                                                                     |
| `service_documentation`                                    | `string`   | URL of a page containing human-readable information that developers might want or need to know when using the OpenID Provider.                                                                                                                                                               |
| `claims_locales_supported`                                 | `string[]` | Languages and scripts supported for values in Claims being returned, represented as a JSON array of BCP47 [RFC5646] language tag values. Not all languages and scripts are necessarily supported for all Claim values.                                                                       |
| `ui_locales_supported`                                     | `string[]` | Languages and scripts supported for the user interface, represented as a JSON array of BCP47 [RFC5646] language tag values.                                                                                                                                                                  |
| `claims_parameter_supported`                               | `boolean`  | Boolean value specifying whether the OP supports use of the claims parameter, with true indicating support. If omitted, the default value is false.                                                                                                                                          |
| `request_parameter_supported`                              | `boolean`  | Boolean value specifying whether the OP supports use of the request parameter, with true indicating support. If omitted, the default value is false.                                                                                                                                         |
| `request_uri_parameter_supported`                          | `boolean`  | Boolean value specifying whether the OP supports use of the request_uri parameter, with true indicating support. If omitted, the default value is true.                                                                                                                                      |
| `require_request_uri_registration`                         | `boolean`  | Boolean value specifying whether the OP requires any request_uri values used to be pre-registered using the request_uris registration parameter.                                                                                                                                             |
| `op_policy_uri`                                            | `string`   | URL that the OpenID Provider provides to the person registering the Client to read about the OP's requirements on how the Relying Party can use the data provided by the OP.                                                                                                                 |
| `op_tos_uri`                                               | `string`   | URL that the OpenID Provider provides to the person registering the Client to read about OpenID Provider's terms of service.                                                                                                                                                                 |
| `revocation_endpoint`                                      | `string`   | URL of the authorization server's OAuth 2.0 revocation endpoint.                                                                                                                                                                                                                             |
| `revocation_endpoint_auth_methods_supported`               | `string[]` | JSON array containing a list of client authentication methods supported by this revocation endpoint.                                                                                                                                                                                         |
| `revocation_endpoint_auth_signing_alg_values_supported`    | `string[]` | JSON array containing a list of the JWS signing algorithms ("alg" values) supported by the revocation endpoint for the signature on the JWT [JWT] used to authenticate the client at the revocation endpoint for the "private_key_jwt" and "client_secret_jwt" authentication methods.       |
| `introspection_endpoint`                                   | `string`   | URL of the authorization server's OAuth 2.0 introspection endpoint.                                                                                                                                                                                                                          |
| `introspection_endpoint_auth_methods_supported`            | `string[]` | JSON array containing a list of client authentication methods supported by this introspection endpoint.                                                                                                                                                                                      |
| `introspection_endpoint_auth_signing_alg_values_supported` | `string[]` | JSON array containing a list of the JWS signing algorithms ("alg" values) supported by the introspection endpoint for the signature on the JWT [JWT] used to authenticate the client at the introspection endpoint for the "private_key_jwt" and "client_secret_jwt" authentication methods. |
| `code_challenge_methods_supported`                         | `string[]` | JSON array containing a list of Proof Key for Code Exchange (PKCE) [RFC7636] code challenge methods supported by this authorization server.                                                                                                                                                  |
| `check_session_iframe`                                     | `string`   | URL of an OP iframe that supports cross-origin communications for session state information with the RP Client, using the HTML5 postMessage API.                                                                                                                                             |
| `end_session_endpoint`                                     | `string`   | URL at the OP to which an RP can perform a redirect to request that the End-User be logged out at the OP.                                                                                                                                                                                    |
| `backchannel_logout_supported`                             | `boolean`  | Boolean value specifying whether the OP supports back-channel logout, with true indicating support. If omitted, the default value is false.                                                                                                                                                  |
| `backchannel_logout_session_supported`                     | `boolean`  | Boolean value specifying whether the OP can pass a sid (session ID) Claim in the Logout Token to identify the RP session with the OP.                                                                                                                                                        |

### TemporaryData

Temporary data accepts any key-value pair.
| Attribute       | Type     |
|-----------------|----------|
| [key: `string`] | `string` |

### StoreValue

The `StoreValue` is a type that accepts strings, string arrays, booleans, numbers and `OIDCEndpoints`.

```TypeScript
type StoreValue = string | string[] | boolean | number | OIDCEndpoints;
```

### BasicUserInfo

| Attribute       | Type     | Description                                                                                        |
|:----------------|:---------|:---------------------------------------------------------------------------------------------------|
| `email`         | `string` | The email address of the user.                                                                     |
| `username`      | `string` | The username of the user.                                                                          |
| `displayName`   | `string` | The display name of the user. It is the `preferred_username` in the id token payload or the `sub`. |
| `allowedScopes` | `string` | The scopes allowed for the user.                                                                   |
| `tenantDomain`  | `string` | The tenant domain to which the user belongs.                                                       |
| `sessionState`  | `string` | The session state.                                                                                 |
| `sub`           | `string` | The `uid` corresponding to the user to whom the ID token belongs to.                               |

In addition to the above attributes, this object will also contain any other claim found in the ID token payload.

### JWKInterface

| Attribute | Type     | Description                                                        |
|-----------|----------|--------------------------------------------------------------------|
| `kty`     | `string` | The type of the key. Must be one of `RSA`, `EC`, `oct` or `OKP`.   |
| `kid`     | `string` | The key ID.                                                        |
| `use`     | `string` | The intended use of the public key. Must be one of `sig` or `enc`. |
| `alg`     | `string` | The algorithm intended for use with the key.                       |
| `n`       | `string` | The public modulus.                                                |
| `e`       | `string` | The public exponent.                                               |

## Develop

### Prerequisites

-   `Node.js` (version 10 or above).
-   `yarn` package manager.

### Installing Dependencies

The repository is a mono repository. The SDK repository is found in the [lib](https://github.com/asgardeo/asgardeo-auth-js-sdk/tree/master/lib) directory. You can install the dependencies by running the following command at the root.

```
yarn build
```

## Error Codes

Error code consist of four parts separated by a `-`.

-   The first part refers to the SDK. Example: `JS` refers to this SDK.
-   The second part refers to the code file. Example: `AUTH_CORE` refers to the `authentication-core.ts` file.
-   The third part is the abbreviation of the name of the method/function that threw the error. If there are more than one method/function with the same abbreviation, then a number based on the order of declaration is appended to the abbreviation. Example: `RAT1` refers to the `requestAccessToken` method. There are two methods that can be abbreviated to `RAT` but since `1` has been appended to `RAT`, we know it refers to `requestAccessToken` since it is declared first.
-   The fourth part refers to the type of error and is position. Example: `NE02` refers to a network error and the fact that this is the second error in the method/function. The following error types are available:

    | Error Code | Description   |
    |:-----------|:--------------|
    | `NE`       | Network Error |
    | `HE`       | Http Error    |
    | `IV`       | Invalid       |
    | `NF`       | Not Found     |
    | `TO`       | Timeout       |
    | `SE`       | Server Error  |

## Contribute

Please read [Contributing to the Code Base](http://wso2.github.io/) for details on our code of conduct, and the process for submitting pull requests to us.

### Reporting issues

We encourage you to report issues, improvements, and feature requests creating [Github Issues](https://github.com/asgardeo/asgardeo-auth-js-sdk/issues).

Important: And please be advised that security issues must be reported to security@wso2com, not as GitHub issues, in order to reach the proper audience. We strongly advise following the WSO2 Security Vulnerability Reporting Guidelines when reporting the security issues.

## License

This project is licensed under the Apache License 2.0. See the [LICENSE](LICENSE) file for details.
