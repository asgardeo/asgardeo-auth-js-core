# Asgardeo JavaScript Auth SDK
[![Stackoverflow](https://img.shields.io/badge/Ask%20for%20help%20on-Stackoverflow-orange)](https://stackoverflow.com/questions/tagged/wso2is)
[![Join the chat at https://join.slack.com/t/wso2is/shared_invite/enQtNzk0MTI1OTg5NjM1LTllODZiMTYzMmY0YzljYjdhZGExZWVkZDUxOWVjZDJkZGIzNTE1NDllYWFhM2MyOGFjMDlkYzJjODJhOWQ4YjE](https://img.shields.io/badge/Join%20us%20on-Slack-%23e01563.svg)](https://join.slack.com/t/wso2is/shared_invite/enQtNzk0MTI1OTg5NjM1LTllODZiMTYzMmY0YzljYjdhZGExZWVkZDUxOWVjZDJkZGIzNTE1NDllYWFhM2MyOGFjMDlkYzJjODJhOWQ4YjE)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://github.com/wso2/product-is/blob/master/LICENSE)
[![Twitter](https://img.shields.io/twitter/follow/wso2.svg?style=social&label=Follow)](https://twitter.com/intent/follow?screen_name=wso2)

## Table of Content

## Introduction
Asgardeo's JavaScript Auth SDK provides the core methods that are needed to implement OIDC authentication in JavaScript/TypeScript based apps. This SDK can be used to build SDKs for Single Page Applications, React Native, Node.JS and various other frameworks that use JavaScript.

## Install
Install the library from the npm registry.
```
npm install @asgardeo/auth-js
```

Or simply load the SDK by importing the script into the header of your HTML file.
```html
<script src="https://unpkg.com/@asgardeo/auth-js@0.1.26/dist/asgardeo-oidc.production.min.js.js"></script>
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
auth.getAuthorizationURL().then((url)=>{
    // Redirect the user to the authentication URL. If this is used in a browser,
    // you may want to do something like this:
    window.location.href = url;
}).catch((error)=>{
    console.error(error);
});

// Once you obtain the authentication code and the session state from the server, you can use this method
// to get the access token.
auth.requestAccessToken().then((response)=>{
    // Obtain the token and other related from the response;
    console.log(response);
}).catch((error)=>{
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
auth.getAuthorizationURL().then((url)=>{
    // Redirect the user to the authentication URL. If this is used in a browser,
    // you may want to do something like this:
    window.location.href = url;
}).catch((error)=>{
    console.error(error);
});

// Once you obtain the authentication code and the session state from the server, you can use this method
// to get the access token.
auth.requestAccessToken().then((response)=>{
    // Obtain the token and other related from the response;
    console.log(response);
}).catch((error)=>{
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

**Note that using a polyfilled modules comes at the cost of the bundle size being twice as big as the default, non-polyfilled bundle.**

## APIs
### constructor
```TypeScript
new AsgardeoAuthClient(config: AuthClientConfig<T>);
```
#### Arguments
1. config: `AuthClientConfig<T>`

    This contains the configuration information needed to implement authentication such as the client ID, server origin etc. Additional configuration information that is needed to be stored can be passed by extending the type of this argument using the generic type parameter. For example, if you want the config to have an attribute called `foo`, you can create an interface called `Bar` in TypeScript and then pass that interface as the generic type to `AuthClientConfig` interface.

    ```TypeScript
    interface Bar {
        foo: string
    }

    const auth = new AsgardeoAuthClient(config: AuthClientConfig<Bar>);
    }
    ```

2. store: `Store`

    This is the object of interface `Store` that is used by the SDK to store all the necessary data used ranging from the configuration data to the access token. You can implement the Store to create a class with your own implementation logic and pass an instance of the class as the second argument. This way, you will be able to get the data stored in your preferred place. To know more about implementing the `Store` interface, refer to the [Data Storage](#data-storage) section.

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
dataLayer : `DataLayer`

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
getAuthorizationURL(config?: AuthorizationURLParams): Promise<string>
```
#### Arguments
1. config: `AuthorizationURLParams` (optional)

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
A Promise that resolves with the [`TokenResponse`](#token-response) object.

The object contains data returned by the token response such as the access token, id token, refresh token, etc. You can learn more about the data returned from the [`TokenResponse`](#token-response) section.

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
This clears the authentication data from the store, generates the sign-out URL and returns it. This should be used only if you want to sign out the user from the identity server as well. If you only want to revoke the access token, then use the [`revokeAccessToken`](#revoke-access-token) method.

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
This method returns the sign-out URL to which the user should be redirected to be signed out from the server. This is different to the [`signOut`](#sign-out) method because **this doesn't clear the authentication data** from the store.

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
oidcEndpoints: OIDCEndpoints

An object containing the OIDC service endpoints returned by the `.well-known` endpoint.

#### Description
This method returns the OIDC service endpoints obtained from the `.well-known` endpoint. To learn more about what endpoints are returned, checkout the [`OIDCEndpoints`](#oidc-endpoints) section.

#### Example
```TypeScript
const oidcEndpoints = auth.getOIDCServiceEndpoints();
```
---
### getDecodedIDToken
```TypeScript
getDecodedIDToken(): DecodedIdTokenPayload
```
#### Returns
decodedIDTokenPayload: DecodedIdTokenPayload
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
basicUserInfo: BasicUserInfo
An object containing basic user information obtained from the id token.

#### Description
This method returns the basic user information obtained from the payload. To learn more about what information is returned, checkout the [`DecodedIdTokenPayload`](#decoded-id-token-payload) model.

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
This method sends a refresh-token request and returns a promise that resolves with the token information. To learn more about what information is returned, checkout the [`TokenResponse`](#token-response) model. The existing authentication data in the store is automatically updated with the new information returned by this request.

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
This method returns the access token stored in the store. If you want to send a request to obtain the access token from the server, use the [`requestAccessToken`](#request-access-token) method.

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
1. config: `CustomGrantConfig`
The config object contains attributes that would be used to configure the custom grant request. To learn more about the different configurations available, checkout the [`CustomGrantConfig`](#custom-grant-config) model.

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
This code returns the PKCE code generated when the authorization URL is generated by the [`getAuthorizationURL`](#get-authorization-url) method.

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

The PKCE code generated by the [`getAuthorizationURL`](#get-authorization-url) method.

#### Description
This method sets the PKCE code to the store. The PKCE code is usually stored in the store by the SDK. But there could be instances when the store could be cleared such as when the data is stored in the memory and the user is redirected to the authorization endpoint in a Single Page Application. When the user is redirected back to the app, the authorization code, session state, and the PKCE code will have to be sent to the server to obtain the access token. However, since, during redirection, everything in the memory is cleared, the PKCE code cannot be obtained. In such instances, the [`getPKCECode()`](#get-pkce-code) method can be used to get the PKCE code before redirection and store it in a place from where it can be retrieved after redirection, and then this method can be used to save the PKCE code to the store so that the [`requestAccessToken`](#request-access-token) method can run successfully.

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
This method returns if the user has been successfully signed out or not. When a user signs out from the server, the user is redirected to the URL specified by the `signOutRedirectURL` in the config object passed into the constructor of the `asgardeoAuthClient`. The server appends path parameters indicating if the sign-out is successful. This method reads the URL and returns if the sign-out is successful or not. So, make sure you pass as the argument, the URL to which the user has been redirected to after signing out from the server.

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
1. config: `AuthClientConfig<T>`

The config object containing the attributes that can be used to configure the SDK. To learn more about the available attributes, refer to the [`AuthClientConfig>T>`](#auth-client-config) model.

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

## Models
### AuthClientConfig<T>
### Store
### AuthorizationURLParams
### TokenResponse
### OIDCEndpoints
### DecodedIdTokenPayload
### CustomGrantConfig
