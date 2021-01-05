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
     signInRedirectURL: "http://localhost:9443/myaccount/login",
     signOutRedirectURL: "http://localhost:9443/myaccount/login",
     clientHost: "http://localhost:9443/myaccount/",
     clientID: "client ID",
     serverOrigin: "http://localhost:9443"
};

// Create a Store class to store the authentication data. The following implementation uses teh session storage.
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
     signInRedirectURL: "http://localhost:9443/myaccount/login",
     signOutRedirectURL: "http://localhost:9443/myaccount/login",
     clientHost: "http://localhost:9443/myaccount/",
     clientID: "client ID",
     serverOrigin: "http://localhost:9443"
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
```
const auth = new AsgardeoAuthClient(config: AuthClientConfig<T>);
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

### getDataLayer
#### Returns
1. dataLayer : `DataLayer`

    A `DataLayer` object wraps the `Store` object passed during object instantiation and provides access to various types of data used by the SDK. To learn more about the various types of interfaces provide by the `DataLayer`, refer to the [Data layer](#data-layer) section.

#### Description
This method returns the `DataLayer` object used by the SDK to store authentication data.

#### Example
```TypeScript
const dataLayer = auth.getDataLayer();
```
### getAuthorizationURL

## Data Storage
### Data Layer
## Models
AuthClientConfig<T>
Store
