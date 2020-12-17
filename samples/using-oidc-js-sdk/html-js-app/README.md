# HTML Javascript Sample Application using Asgardio OIDC JS SDK

## Getting Started

### Register an Application

Follow the instructions in the [Try Out the Sample Apps](../../packages/oidc-js/README.md#try-out-the-sample-apps) section to register an application.

Make sure to add `http://localhost:3000` as a Redirect URL and also add it under allowed origins. 

### Configuring the Sample

1. Update the `authConfig` object in `index.html` with your registered app details.

Note: You will only have to paste in the `client ID` generated for the application you registered.

Read more about the SDK configurations [here](../../packages/oidc-js/README.md#initialize) .

```js
const authConfig = {
    // Web App URL
    clientHost: webAppOrigin,
    // ClientID generated for the application
    clientID: "<ADD_CLIENT_ID_HERE>",
    // After login callback URL - We have use app root as this is a SPA
    // (Add it in application OIDC settings "Callback Url")
    signInRedirectURL: webAppOrigin,
    // After logout callback URL - We have use app root as this is a SPA
    // (Add it in application OIDC settings "Callback Url")
    signOutRedirectURL: webAppOrigin,
    // WSO2 Identity Server URL
    serverOrigin: "https://localhost:9443",
    // Storage Strategy. Supported Values are `localStorage`, `sessionStorage` & `webWorker`.
    storage: "sessionStorage",
    // Enables/ Disables PKCE flow.
    enablePKCE: true
};
```

### Run the Application

Note: If you are deploying and testing out this sample in your own server environment, just adding the static files would be enough.
The following steps demonstrates the usage of a 3rd party module to serve up the static content.

### Install Dependencies

The sample is using [http-server](https://www.npmjs.com/package/http-server) package to serve the static files.
You have to install it through npm.

```bash
npm install
```

### Starting the server

```bash
npm start
```

The app should open at `http://localhost:3000`

## License

Licenses this source under the Apache License, Version 2.0 ([LICENSE](../../../LICENSE)), You may not use this file except in compliance with the License.
