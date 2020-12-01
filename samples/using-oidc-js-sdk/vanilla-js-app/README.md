# Asgardio Vanilla JavaScript Sample App
## Getting Started
Before getting started with running this app, make sure you have followed the instructions in the [Try Out the Sample Apps](../../README.md#try-out-the-sample-apps) section.


Open the [index.html](index.html) file. Scroll down to the `<script>` tag below the `body` where the app logic is written.

Paste the copied `OAuth Client Key` in front of the `clientID` attribute of `auth.initialize` method's argument object. You will be replacing a value called `client-id`.
```javascript
 // Initialize the client
auth.initialize({
    baseUrls: [ serverOrigin ],
    signInRedirectURL: clientHost,
    clientHost: clientHost,
    clientID: "client-id",
    serverOrigin: serverOrigin,
    storage: "webWorker"
});
```

Run the app by entering the following command
```
npm start
```
The app should open at `http://localhost:3000`
