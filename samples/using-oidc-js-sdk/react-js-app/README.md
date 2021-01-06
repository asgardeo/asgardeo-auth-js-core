# React JS Sample Application using Asgardio Auth JS SDK

## Getting Started

### Register an Application

Follow the instructions in the [Try Out the Sample Apps](../../packages/oidc-js/README.md#try-out-the-sample-apps) section to register an application.

Make sure to add `https://localhost:5000` as a Redirect URL and also add it under allowed origins. 

### Configuring the Sample

1. Update configuration file `src/config.json` with your registered app details.

Note: You will only have to paste in the `client ID` generated for the application you registered.

Read more about the SDK configurations [here](../../packages/oidc-js/README.md#initialize) .

```json
{
    "clientID": "<ADD_CLIENT_ID_HERE>",
    "serverOrigin": "https://localhost:9443",
    "signInRedirectURL": "https://localhost:5000",
    "signOutRedirectURL": "https://localhost:5000"
}
```

### Run the Application

```bash
npm start
```

The app should open at `https://localhost:5000`

## License

Licenses this source under the Apache License, Version 2.0 ([LICENSE](../../../LICENSE)), You may not use this file except in compliance with the License.
