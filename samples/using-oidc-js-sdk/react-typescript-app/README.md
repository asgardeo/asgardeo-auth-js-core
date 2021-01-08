# React Typescript Sample Application using Asgardio OIDC JS SDK

## Getting Started

### Register an Application

Follow the instructions in the [Try Out the Sample Apps](../../../packages/oidc-js/README.md#try-out-the-sample-apps) section to register an application.

Make sure to add `http://localhost:3000` as a Redirect URL and also add it under allowed origins. 

### Configuring the Sample

1. Update configuration file `src/config.json` with your registered app details.

Note: You will only have to paste in the `client ID` generated for the application you registered.

Read more about the SDK configurations [here](../../../packages/oidc-js/README.md#initialize) .

```json
{
    "clientID": "<ADD_CLIENT_ID_HERE>",
    "serverOrigin": "https://localhost:9443",
    "signInRedirectURL": "http://localhost:3000",
    "signOutRedirectURL": "http://localhost:3000",
    "storage": "sessionStorage"
}
```

### Run the Application

```bash
npm start
```

The app should open at `http://localhost:3000`

## Available Scripts

In the project directory, you can run:

### `npm start`

Runs the app in the development mode.<br />
Open [http://localhost:3000](http://localhost:3000) to view it in the browser.

The page will reload if you make edits.<br />
You will also see any lint errors in the console.

### `npm run build`

Builds the app for production to the `build` folder.<br />
It correctly bundles React in production mode and optimizes the build for the best performance.

The build is minified and the filenames include the hashes.<br />
Your app is ready to be deployed!

## License

Licenses this source under the Apache License, Version 2.0 ([LICENSE](../../../LICENSE)), You may not use this file except in compliance with the License.
