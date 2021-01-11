# Asgardeo JavaScript Auth SDK

[![Stackoverflow](https://img.shields.io/badge/Ask%20for%20help%20on-Stackoverflow-orange)](https://stackoverflow.com/questions/tagged/wso2is)
[![Join the chat at https://join.slack.com/t/wso2is/shared_invite/enQtNzk0MTI1OTg5NjM1LTllODZiMTYzMmY0YzljYjdhZGExZWVkZDUxOWVjZDJkZGIzNTE1NDllYWFhM2MyOGFjMDlkYzJjODJhOWQ4YjE](https://img.shields.io/badge/Join%20us%20on-Slack-%23e01563.svg)](https://join.slack.com/t/wso2is/shared_invite/enQtNzk0MTI1OTg5NjM1LTllODZiMTYzMmY0YzljYjdhZGExZWVkZDUxOWVjZDJkZGIzNTE1NDllYWFhM2MyOGFjMDlkYzJjODJhOWQ4YjE)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://github.com/wso2/product-is/blob/master/LICENSE)
[![Twitter](https://img.shields.io/twitter/follow/wso2.svg?style=social&label=Follow)](https://twitter.com/intent/follow?screen_name=wso2)

## Table of Content

-   [Introduction](#introduction)
-   [Install](#install)
-   [Getting Started](#getting-started)
    -   [Using an Embedded Script](#using-an-embedded-script)
    -   [Using a Module](#using-a-module)
-   [Browser Compatibility](#browser-compatibility)
-   [APIs](#apis)
    -   [constructor](#constructor)
    -   [getDataLayer](#getDataLayer)
    -   [getAuthorizationURL](#getAuthorizationURL)
    -   [requestAccessToken](#requestAccessToken)
    -   [signOut](#signOut)
    -   [getSignOutURL](#getSignOutURL)
    -   [getOIDCServiceEndpoints](#getOIDCServiceEndpoints)
    -   [getDecodedIDToken](#getDecodedIDToken)
    -   [getBasicUserInfo](#getBasicUserInfo)
    -   [revokeAccessToken](#revokeAccessToken)
    -   [refreshAccessToken](#refreshAccessToken)
    -   [getAccessToken](#getAccessToken)
    -   [requestCustomGrant](#requestCustomGrant)
    -   [isAuthenticated](#isAuthenticated)
    -   [getPKCECode](#getPKCECode)
    -   [setPKCECode](#setPKCECode)
    -   [isSignOutSuccessful](#isSignOutSuccessful)
    -   [updateConfig](#updateConfig)
-   [Data Storage](#data-storage)
    -   [Data Layer](#data-layer)
-   [Models](#models)
    -   [AuthClientConfig\<T>](#AuthClientConfig<T>)
    -   [Store](#Store)
    -   [SignInConfig](#SignInConfig)
    -   [TokenResponse](#TokenResponse)
    -   [OIDCEndpoints](#OIDCEndpoints)
    -   [DecodedIDTokenPayload](#DecodedIDTokenPayload)
    -   [CustomGrantConfig](#CustomGrantConfig)
        -   [Custom Grant Template Tags](#Custom-Grant-Template-Tags)
    -   [SessionData](#SessionData)
    -   [OIDCProviderMetaData](#OIDCProviderMetaData)
    -   [TemporaryData](#TemporaryData)
    -   [BasicUserInfo](#BasicUserInfo)
-   [Develop](#develop)
-   [Contribute](#contribute)
-   [License](#license)

## Introduction

Asgardeo's JavaScript Auth SDK provides the core methods that are needed to implement OIDC authentication in JavaScript/TypeScript based apps. This SDK can be used to build SDKs for Single Page Applications, React Native, Node.JS and various other frameworks that use JavaScript.

## Install

Install the library from the npm registry.

```
npm install @asgardeo/auth-js
```

Or simply load the SDK by importing the script into the header of your HTML file.

```html
<script src="https://unpkg.com/@asgardeo/auth-js@0.1.26/dist/asgardeo-auth.production.min.js"></script>
```

If you want a polyfilled version of the SDK, checkout the [Browser Compatibility](#browser-compatibility) section.

## Getting Started

### Using an Embedded Script

```javascript
// Create a config object containing the necessary configurations.
const config = {
    signInRedirectURL: "http://localhost:3000/sign-in",
    signOutRedirectURL: "http://localhost:3000/dashboard",
    clientHost: "http://localhost:3000",
    clientID: "client ID",
    serverOrigin: "https://localhost:9443"
};

// Create a Store class to store the authentication data. The following implementation uses the session storage.
class SessionStore {
    // Saves the data to the store.
    setData(key, value) {
        sessionStorage.setItem(key, value);
    }

    // Gets the data from the store.
    getData(key) {
        return sessionStorage.getItem(key);
    }

    // Removes the date from the store.
    removeData(key) {
        sessionStorage.removeItem(key);
    }
}

// Instantiate the SessionStore class
const store = new SessionStore();

// Instantiate the AsgardeoAuthClient and pass the config object and the store object as an argument into the constructor.
const auth = new AsgardeoAuth.AsgardeoAuthClient(config, store);

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
auth.requestAccessToken()
    .then((response) => {
        // Obtain the token and other related from the response;
        console.log(response);
    })
    .catch((error) => {
        console.error(error);
    });
```

### Using a Module

```javascript
// The SDK provides a client that can be used to carry out the authentication.
import { AsgardeoAuthClient } from "@asgardeo/auth-js";

// Create a config object containing the necessary configurations.
const config = {
    signInRedirectURL: "http://localhost:3000/sign-in",
    signOutRedirectURL: "http://localhost:3000/dashboard",
    clientHost: "http://localhost:3000",
    clientID: "client ID",
    serverOrigin: "https://localhost:9443"
};

// Create a Store class to store the authentication data. The following implementation uses the session storage.
class SessionStore {
    // Saves the data to the store.
    setData(key, value) {
        sessionStorage.setItem(key, value);
    }

    // Gets the data from the store.
    getData(key) {
        return sessionStorage.getItem(key);
    }

    // Removes the date from the store.
    removeData(key) {
        sessionStorage.removeItem(key);
    }
}

// Instantiate the SessionStore class
const store = new SessionStore();

// Instantiate the AsgardeoAuthClient and pass the config object and the store object as an argument into the constructor.
const auth = new AsgardeoAuthClient(config, store);

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
auth.requestAccessToken()
    .then((response) => {
        // Obtain the token and other related from the response;
        console.log(response);
    })
    .catch((error) => {
        console.error(error);
    });
```

[Learn more](#apis).

## Browser Compatibility

The SDK supports all major browsers and provides polyfills to support incompatible browsers. If you want the SDK to run on Internet Explorer or any other old browser, you can use the polyfilled script instead of the default one.

To embed a polyfilled script in an HTML page:

```html
<script src="https://unpkg.com/@asgardeo/auth-js@0.1.26/dist/polyfilled/asgardeo-oidc.production.min.js.js"></script>
```

You can also import a polyfilled module into your modular app. Asgardeo provides two different modules each supporting UMD and ESM.
You can specify the preferred module type by appending the type to the module name as follows.

To import a polyfilled ESM module:

```javascript
import { AsgardeoSPAClient } from "@asgardeo/auth-js/polyfilled/esm";
```

To import a polyfilled UMD module:

```javascript
import { AsgardeoSPAClient } from "@asgardeo/auth-js/polyfilled/umd";
```

**Note that using a polyfilled modules comes at the cost of the bundle size being twice as big as the default non-polyfilled bundle.**

## APIs

The SDK provides a client class called `AsgardeoAuthClient` that provides you with the necessary methods to implement authentication.
You can instantiate the class and use the object to access the provided methods.

### constructor

```TypeScript
new AsgardeoAuthClient(config: AuthClientConfig<T>);
```

#### Arguments

1. config: [`AuthClientConfig<T>`](#AuthClientConfig<T>)

    This contains the configuration information needed to implement authentication such as the client ID, server origin etc. Additional configuration information that is needed to be stored can be passed by extending the type of this argument using the generic type parameter. For example, if you want the config to have an attribute called `foo`, you can create an interface called `Bar` in TypeScript and then pass that interface as the generic type to `AuthClientConfig` interface. To learn more about what attributes can be passed into this object, refer to the [`AuthClientConfig<T>`](#AuthClientConfig<T>) section.

    ```TypeScript
    interface Bar {
        foo: string
    }

    const auth = new AsgardeoAuthClient(config: AuthClientConfig<Bar>);
    }
    ```

2. store: [`Store`](#Store)

    This is the object of interface [`Store`](#Store) that is used by the SDK to store all the necessary data used ranging from the configuration data to the access token. You can implement the Store to create a class with your own implementation logic and pass an instance of the class as the second argument. This way, you will be able to get the data stored in your preferred place. To know more about implementing the [`Store`](#Store) interface, refer to the [Data Storage](#data-storage) section.

#### Description

This creates an instance of the `AsgardeoAuthClient` class and returns it.

#### Example

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

const store = new SessionStore();

const auth = new AsgardeoAuthClient(config, store);
```

---

### getDataLayer

```TypeScript
getDatLayer(): DataLayer<T>
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

### getAuthorizationURL

```TypeScript
getAuthorizationURL(config?: SignInConfig): Promise<string>
```

#### Arguments

1. config: [`SignInConfig`](#SignInConfig) (optional)

    An optional config object that has the necessary attributes to configure this method. The `forceInit` attribute can be set to `true` to trigger a request to the `.well-known` endpoint and obtain the OIDC endpoints. By default, a request to the `.well-known` endpoint will be sent only if a request to it had not been sent before. If you wish to force a request to the endpoint, you can use this attribute.

    The object can only contain key-value pairs that you wish to append as path parameters to the authorization URL. For example, to set the `fidp` parameter, you can insert `fidp` as a key and its value to this object.

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
requestAccessToken(authorizationCode: string, sessionState: string): Promise<TokenResponse>
```

#### Arguments

1. authorizationCode: `string`

    This is the authorization code obtained from the identity server after a user signs in.

2. sessionState: `string`

    This is the session state obtained from the identity server after a user signs in.

#### Returns

A Promise that resolves with the [`TokenResponse`](#TokenResponse) object.

The object contains data returned by the token response such as the access token, id token, refresh token, etc. You can learn more about the data returned from the [`TokenResponse`](#TokenResponse) section.

#### Description

This method uses the authorization code and the session state that are passed as arguments to send a request to the `token` endpoint to obtain the access token and the id token. The sign-in functionality can be implemented by calling the [`getAuthorizationURL`](#getAuthorizationURL) method followed by this method.

#### Example

```TypeScript
auth.requestAccessToken("auth-code", "session-state").then((tokenResponse)=>{
    console.log(tokenResponse);
}).catch((error)=>{
    console.error(error);
});
```

---

### signOut

```TypeScript
signOut(): string
```

#### Returns

signOutURL: `string`

The user should be redirected to this URL in order to sign out of the server.

#### Description

This clears the authentication data from the store, generates the sign-out URL and returns it. This should be used only if you want to sign out the user from the identity server as well. If you only want to revoke the access token, then use the [`revokeAccessToken`](#revokeAccessToken) method.

#### Example

```TypeScript
const signOutURL = auth.signOut();
```

---

### getSignOutURL

```TypeScript
getSignOutURL(): string
```

#### Returns

signOutURL: `string`

The user should be redirected to this URL in order to sign out of the server.

#### Description

This method returns the sign-out URL to which the user should be redirected to be signed out from the server. This is different to the [`signOut`](#signOut) method because **this doesn't clear the authentication data** from the store.

#### Example

```TypeScript
const signOutURL = auth.getSignOutURL();
```

---

### getOIDCServiceEndpoints

```TypeScript
getOIDCServiceEndpoints(): OIDCEndpoints
```

#### Returns

oidcEndpoints: [`OIDCEndpoints`](#OIDCEndpoints)

An object containing the OIDC service endpoints returned by the `.well-known` endpoint.

#### Description

This method returns the OIDC service endpoints obtained from the `.well-known` endpoint. To learn more about what endpoints are returned, checkout the [`OIDCEndpoints`](#OIDCEndpoints) section.

#### Example

```TypeScript
const oidcEndpoints = auth.getOIDCServiceEndpoints();
```

---

### getDecodedIDToken

```TypeScript
getDecodedIDToken(): DecodedIDTokenPayload
```

#### Returns

decodedIDTokenPayload: [`DecodedIDTokenPayload`](#DecodedIDTokenPayload)
The decoded ID token payload.

#### Description

This method decodes the payload of the id token and returns the decoded values.

#### Example

```TypeScript
const decodedIDTokenPayload = auth.getDecodedIDToken();
```

---

### getBasicUserInfo

```TypeScript
getBasicUserInfo(): BasicUserInfo
```

#### Returns

basicUserInfo: [`BasicUserInfo`](#BasicUserInfo)
An object containing basic user information obtained from the id token.

#### Description

This method returns the basic user information obtained from the payload. To learn more about what information is returned, checkout the [`DecodedIDTokenPayload`](#DecodedIDTokenPayload) model.

#### Example

```TypeScript
const basicUserInfo = auth.getBasicUserInfo();
```

---

### revokeAccessToken

```TypeScript
revokeAccessToken(): Promise<AxiosResponse>
```

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
refreshAccessToken(): Promise<TokenResponse>
```

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
getAccessToken(): string
```

#### Returns

accessToken: `string`
The access token.

#### Description

This method returns the access token stored in the store. If you want to send a request to obtain the access token from the server, use the [`requestAccessToken`](#requestAccessToken) method.

#### Example

```TypeScript
const accessToken = auth.getAccessToken();
```

---

### requestCustomGrant

```TypeScript
requestCustomGrant(config: CustomGrantConfig): Promise<TokenResponse | AxiosResponse>
```

#### Arguments

1. config: [`CustomGrantConfig`](#CustomGrantConfig)
   The config object contains attributes that would be used to configure the custom grant request. To learn more about the different configurations available, checkout the [`CustomGrantConfig`](#CustomGrantConfig) model.

#### Returns

A Promise that resolves with the token information or the response returned by the server depending on the configuration passed.

#### Description

This method can be used to send custom-grant requests to the identity server.

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
isAuthenticated(): boolean
```

#### Returns

isAuth: `boolean`
A boolean value that indicates of the user is authenticated or not.

#### Description

This method returns a boolean value indicating if the user is authenticated or not.

#### Example

```TypeScript
const isAuth = auth.isAuthenticated();
```

---

### getPKCECode

```TypeScript
getPKCECode(): string
```

#### Returns

pkce: `string`

The PKCE code

#### Description

This code returns the PKCE code generated when the authorization URL is generated by the [`getAuthorizationURL`](#getAuthorizationURL) method.

#### Example

```TypeScript
const pkce = auth.getPKCECode();
```

---

### setPKCECode

```TypeScript
setPKCECode(pkce: string): void
```

#### Arguments

1. pkce: `string`

The PKCE code generated by the [`getAuthorizationURL`](#getAuthorizationURL) method.

#### Description

This method sets the PKCE code to the store. The PKCE code is usually stored in the store by the SDK. But there could be instances when the store could be cleared such as when the data is stored in the memory and the user is redirected to the authorization endpoint in a Single Page Application. When the user is redirected back to the app, the authorization code, session state, and the PKCE code will have to be sent to the server to obtain the access token. However, since, during redirection, everything in the memory is cleared, the PKCE code cannot be obtained. In such instances, the [`getPKCECode`](#getPKCECode) method can be used to get the PKCE code before redirection and store it in a place from where it can be retrieved after redirection, and then this method can be used to save the PKCE code to the store so that the [`requestAccessToken`](#requestAccessToken) method can run successfully.

#### Example

```TypeScript
auth.setPKCECode("pkce");
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

This method returns if the user has been successfully signed out or not. When a user signs out from the server, the user is redirected to the URL specified by the `signOutRedirectURL` in the config object passed into the constructor of the `AsgardeoAuthClient`. The server appends path parameters indicating if the sign-out is successful. This method reads the URL and returns if the sign-out is successful or not. So, make sure you pass as the argument, the URL to which the user has been redirected to after signing out from the server.

#### Example

```TypeScript
const isSignedOut = auth.isSignOutSuccessful(window.location.href);
```

---

### updateConfig

```TypeScript
updateConfig(config: Partial<AuthClientConfig<T>>): void
```

#### Arguments

1. config: [`AuthClientConfig<T>`](#AuthClientConfig<T>)

The config object containing the attributes that can be used to configure the SDK. To learn more about the available attributes, refer to the [`AuthClientConfig>T>`](#AuthClientConfig<T>) model.

#### Description

This method can be used to update the configurations passed into the constructor of the `AsgardeoAuthClient`. Please note that every attribute in the config object passed as the argument here is optional. Use this method if you want to update certain attributes after instantiating the class.

#### Example

```TypeScript
auth.updateConfig({
    signOutRedirectURL: "http://localhost:3000/sign-out"
});
```

## Data Storage

Since the SDK was developed with the view of being able to support various platforms such as mobile apps, browsers and node JS servers, the SDK allows developers to use their preferred mode of storage. To that end, the SDK allows you to pass a store object when instantiating the `AsgardeoAuthClient`. This store object contains methods that can be used to store, retrieve and delete data. The SDK provides a Store interface that you can implement to create your own Store class. You can refer to the [`Store`](#store) section to learn mire about the `Store` interface.

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
   Stores the config data passed to the constructor. Refer to [`AuthClientConfig<T>`](#AuthClientConfig<T>) for the full list of data stored.
4. Temporary Data
   Stores data that is temporary. In most cases, you wouldn't need this.

All these four keys get methods to set, get and remove data as whole. In addition to this, all these keys get methods to set, get, and remove specific data referred to by their respective keys. The following table describes the methods provided by the data layer.
|Method|Arguments|Returns|Description|
|--|--|--|--|
|setSessionData |sessionData: [`SessionData`](#SessionData) | `void` | Saves session data in bulk.|
|setOIDCProviderMetaData |oidcProviderMetaData: [`OIDCProviderMetaData`](#OIDCProviderMetaData) | `void` |Saves OIDC Provider Meta data in bulk.|
|setConfigData |config: [`AuthClientConfig<T>`](#AuthClientConfig<T>) | `void` | Saves config data in bulk.|
|setTemporaryData |data: [`TemporaryData`](#TemporaryData) | `void` | Saves temporary data in bulk.|
|getSessionData | | [`SessionData`](#SessionData) | Retrieves session data in bulk.|
|getOIDCProviderMetaData | |[`OIDCProviderMetaData`](#OIDCProviderMetaData) | Retrieves OIDC Provider Meta data in bulk.|
|getConfigData | | [`AuthClientConfig<T>`](#`AuthClientConfig<T>`) | Retrieves config data in bulk.|
|getTemporaryData | | { [key: `string`]: [`StoreValue` ](#StoreValue)} Retrieves temporary data in bulk.| |
|removeSessionData | | `void` | Removes session data in bulk.|
|removeOIDCProviderMetaData | | `void` | Removes OIDC Provider Meta data in bulk.|
|removeConfigData | | `void` | Removes config data in bulk.|
|removeTemporaryData | | `void` | Removes temporary data in bulk.|
|setSessionDataParameter |key: keyof [`SessionData`](#SessionData), value: [`StoreValue`](#StoreValue) | `void` | Saves the passed data against the specified key in the session data.|
|setOIDCProviderMetaDataParameter |key: keyof [`OIDCProviderMetaData`](#OIDCProviderMetaData), value: [`StoreValue`](#StoreValue) | `void` | Saves the passed data against the specified key in the OIDC Provider Meta data.|
|setConfigDataParameter |key: keyof [`AuthClientConfig<T>`](#AuthClientConfig<T>), value: [`StoreValue`](#`StoreValue`) | `void` | Saves the passed data against the specified key in the config data.|
|setTemporaryDataParameter |key: `string`, value: [`StoreValue`](#`StoreValue`) | `void` | Saves the passed data against the specified key in the temporary data.|
|getSessionDataParameter |key: keyof [`SessionData`](#SessionData) | [`StoreValue`](#`StoreValue`) | Retrieves the data for the specified key from the session data.|
|getOIDCProviderMetaDataParameter |key: keyof [`OIDCProviderMetaData`](#OIDCProviderMetaData) | [`StoreValue`](#StoreValue) | Retrieves the data for the specified key from the OIDC Provider Meta data.|
|getConfigDataParameter |key: keyof [`AuthClientConfig<T>`](#AuthClientConfig<T>) | [`StoreValue` ](#StoreValue)| Retrieves the data for the specified key from the config data.|
|getTemporaryDataParameter |key: `string` | [`StoreValue`](#StoreValue) | Retrieves the data for the specified key from the temporary data.|
|removeSessionDataParameter |key: keyof [`SessionData`](#SessionData) | `void` | Removes the data with the specified key from the session data.|
|removeOIDCProviderMetaDataParameter |key: keyof [`OIDCProviderMetaData`](#OIDCProviderMetaData) | `void` | Removes the data with the specified key from the OIDC Provider Meta data.|
|removeConfigDataParameter |key: keyof [`AuthClientConfig<T>`](#AuthClientConfig<T>) | `void` | Removes the data with the specified key from the config data.|
|removeTemporaryDataParameter |key: `string` | `void` | Removes the data with the specified key from the temporary data.|

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
|`serverOrigin`|Required| `string`|""|The origin of the Identity Provider. eg: `https://www.asgardeo.io`|
|`endpoints`|Optional| `OIDCEndpoints`|[OIDC Endpoints Default Values](#oidc-endpoints)|The OIDC endpoint URLs. The SDK will try to obtain the endpoint URLS |using the `.well-known` endpoint. If this fails, the SDK will use these endpoint URLs. If this attribute is not set, then the default endpoint URLs will be |used. However, if the `overrideWellEndpointConfig` is set to `true`, then this will override the endpoints obtained from the `.well-known` endpoint. |
|`overrideWellEndpointConfig`|Optional| `boolean` | `false` | If this option is set to `true`, then the `endpoints` object will override endpoints obtained |from the `.well-known` endpoint. If this is set to `false`, then this will be used as a fallback if the request to the `.well-known` endpoint fails.|
|`wellKnownEndpoint`|Optional| `string`|`"/oauth2/token/.well-known/openid-configuration"`| The URL of the `.well-known` endpoint.|
|`validateIDToken`|Optional| `boolean`|`true`|Allows you to enable/disable JWT ID token validation after obtaining the ID token.|
|`clockTolerance`|Optional| `number`|`60`|Allows you to configure the leeway when validating the id_token.|

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

| Method       | Required/Optional | Arguments                      | Returns                                                                                                                                            | Description                                                                                                                         |
| ------------ | ----------------- | ------------------------------ | -------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------- |
| `setData`    | Required          | key: `string`, value: `string` | `void`                                                                                                                                             | This method saves the passed value to the store. The data to be saved is JSON stringified so will be passed by the SDK as a string. |
| `getData`    | Required          | key: `string`\|`string`        | This method retrieves the data from the store and returns it. Since the SDK stores the data as a JSON string, the returned value will be a string. |
| `removeData` | Required          | key: `string`                  | `void`                                                                                                                                             | Removes the data with the specified key from the store.                                                                             |

### SignInConfig

| Method        | Required/Optional | Type                  | Default Value | Description                                                                                                                                                            |
| ------------- | ----------------- | --------------------- | ------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `fidp`        | Optional          | `string`              | ""            | The `fidp` parameter that can be used to redirect a user directly to an IdP's sign-in page.                                                                            |
| `forceInit`   | Optional          | `boolean`             | `false`       | Forces obtaining the OIDC endpoints from the `.well-known` endpoint. A request to this endpoint is not sent if a request has already been sent. This forces a request. |
| key: `string` | Optional          | `string` \| `boolean` | ""            | Any key-value pair to be appended as path parameters to the authorization URL.                                                                                         |

### TokenResponse

| Method         | Type     | Description                 |
| -------------- | -------- | --------------------------- |
| `accessToken`  | `string` | The access token.           |
| `idToken`      | `string` | The id token.               |
| `expiresIn`    | `string` | The expiry time in seconds. |
| `scope`        | `string` | The scope of the token.     |
| `refreshToken` | `string` | The refresh token.          |
| `tokenType`    | `string` | The token type.             |

### OIDCEndpoints

| Method                  | Type     | Default Value                                      | Description                                                               |
| ----------------------- | -------- | -------------------------------------------------- | ------------------------------------------------------------------------- |
| `authorizationEndpoint` | `string` | `"/oauth2/authorize"`                              | The authorization endpoint.                                               |
| `tokenEndpoint`         | `string` | `"/oauth2/token"`                                  | The token endpoint.                                                       |
| `userinfoEndpoint`      | `string` | ""                                                 | The user-info endpoint.                                                   |
| `jwksUri`               | `string` | `"/oauth2/jwks"`                                   | The JWKS URI.                                                             |
| `registrationEndpoint`  | `string` | ""                                                 | The registration endpoint.                                                |
| `revocationEndpoint`    | `string` | `"/oauth2/revoke"`                                 | The token-revocation endpoint.                                            |
| `introspectionEndpoint` | `string` | ""                                                 | The introspection endpoint.                                               |
| `checkSessionIframe`    | `string` | `"/oidc/checksession"`                             | The check-session endpoint.                                               |
| `endSessionEndpoint`    | `string` | `"/oidc/logout"`                                   | The end-session endpoint.                                                 |
| `issuer`                | `string` | ""                                                 | The issuer of the token.                                                  |
| `wellKnownEndpoint`     | `string` | `"/oauth2/token/.well-known/openid-configuration"` | The well-known endpoint. This is the default endpoint defined in the SDK. |

### DecodedIDTokenPayload

| Method             | Type                   | Description                                    |
| ------------------ | ---------------------- | ---------------------------------------------- |
| aud                | `string` \| `string[]` | The audience.                                  |
| sub                | `string`               | The subject. This is the username of teh user. |
| iss                | `string`               | The token issuer.                              |
| email              | `string`               | The email address.                             |
| preferred_username | `string`               | The preferred username.                        |
| tenant_domain      | `string`               | The tenant domain to which the user belongs.   |

### CustomGrantConfig

| Attribute        | Required/Optional | Type      | Default Value | Description                                                                                                                                                                                                                   |
| ---------------- | ----------------- | --------- | ------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `id`             | Required          | `string`  | ""            | Every custom-grant request should have an id. This attributes takes that id.                                                                                                                                                  |
| `data`           | Required          | `any`     | `null`        | The data that should be sent in the body of the custom-grant request. You can use template tags to send session information. Refer to the [Custom Grant Template Tags](#custom-grant-template-tags) section for more details. |
| `signInRequired` | Required          | `boolean` | `false`       | Specifies if teh user should be sign-in or not to dispatch this custom-grant request.                                                                                                                                         |
| `attachToken`    | Required          | `boolean` | `false`       | Specifies if the access token should be attached to the header of the request.                                                                                                                                                |
| `returnsSession` | Required          | `boolean` | `false`       | Specifies if the the request returns session information such as the access token.                                                                                                                                            |

#### Custom Grant Template Tags

Session information can be attached to the body of a custom-grant request using template tags. This is useful when the session information is not exposed outside the SDK but you want such information to be used in custom-grant requests. The following table lists the available template tags.
|Tag|Data|
|--|--|
|"{{token}}" | The access token.|
|{{username}}" | The username.|
|"{{scope}}" | The scope.|
|{{clientID}}" | The client ID.|
|"{{clientSecret}}" | The client secret.|

### SessionData

| Attribute       | Type     | description                                      |
| --------------- | -------- | ------------------------------------------------ |
| `access_token`  | `string` | The access token.                                |
| `id_token`      | `string` | The id token.                                    |
| `expires_in`    | `string` | The expiry time.                                 |
| `scope`         | `string` | The scope.                                       |
| `refresh_token` | `string` | The refresh token.                               |
| `token_type`    | `string` | The token type.                                  |
| `session_state` | `string` | The session state obtained after authentication. |

### OIDCProviderMetaData

| Attribute                                                  | Type       | description                                                                                                                                                                                                                                                                                  |
| ---------------------------------------------------------- | ---------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
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
|Attribute|Type|
|--|--|
|[key: `string`]|`string`|

### StoreValue

The `StoreValue` is a type that accepts strings, string arrays, booleans, numbers and `OIDCEndpoints`.

```TypeScript
type StoreValue = string | string[] | boolean | number | OIDCEndpoints;
```

### BasicUserInfo

| Attribute       | Type     | Description                                                                                        |
| :-------------- | :------- | :------------------------------------------------------------------------------------------------- |
| `email`         | `string` | The email address of the user.                                                                     |
| `username`      | `string` | The username of the user.                                                                          |
| `displayName`   | `string` | The display name of the user. It is the `preferred_username` in the id token payload or the `sub`. |
| `allowedScopes` | `string` | The scopes allowed for the user.                                                                   |
| `tenantDomain`  | `string` | The tenant domain to which the user belongs.                                                       |
| `sessionState`  | `string` | The session state.                                                                                 |

## Develop

### Prerequisites

-   `Node.js` (version 10 or above).
-   `npm` package manager.

### Installing Dependencies

The repository is a mono repository. The SDK repository is found in the [lib]() directory. You can install the dependencies by running the following command at the root.

```
npm run build
```

## Contribute

Please read [Contributing to the Code Base](http://wso2.github.io/) for details on our code of conduct, and the process for submitting pull requests to us.

### Reporting issues

We encourage you to report issues, improvements, and feature requests creating [Github Issues](https://github.com/asgardeo/asgardeo-auth-js-sdk/issues).

Important: And please be advised that security issues must be reported to security@wso2com, not as GitHub issues, in order to reach the proper audience. We strongly advise following the WSO2 Security Vulnerability Reporting Guidelines when reporting the security issues.

## License

This project is licensed under the Apache License 2.0. See the [LICENSE](LICENSE) file for details.
