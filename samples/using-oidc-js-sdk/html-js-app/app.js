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
 * SDK Client instance.
 */
var auth = AsgardioAuth.IdentityClient.getInstance();

// Initialize the SDK.
initialize();

/**
 * Authenticated State.
 */
var state = {
    isAuth: false,
    displayName: "",
    email: "",
    username: ""
};

/**
 * Initializes the SDK.
 */
function initialize() {

    // Initialize the client with the config object. Check `index.html` for the config object.
    auth.initialize(authConfig)
        .then((response) => {
            // Successfully initialized the SDK client.
        })
        .catch((error) => {
            // Handle the error occurred while initializing the SDK client.
        });

    //Pass the callback function to be called after signing in using the `sign-in` hook
    auth.on("sign-in", function (response) {
        setAuthenticatedState(response);

        sessionStorage.setItem("isInitLogin", "false");

        updateView();
    });
}

/**
 * Updates the view after a login or logout.
 */
function updateView() {

    if (state.isAuth) {
        document.getElementById("text-display-name").innerHTML = state.displayName;
        document.getElementById("text-userame").innerHTML = state.username;
        document.getElementById("text-email").innerHTML = state.email;

        document.getElementById("logged-in-view").style.display = "block";
        document.getElementById("logged-out-view").style.display = "none";
    } else {
        document.getElementById("logged-in-view").style.display = "none";
        document.getElementById("logged-out-view").style.display = "block";
    }
}

/**
 * Sets the authenticated user's information & auth state.
 */
function setAuthenticatedState(response) {

    state.displayName = response.displayName;
    state.email = (response.email !== null && response.email !== "null")
    && (response.email.length && response.email.length > 0)
        ? response.email[0]
        : "";
    state.username = response.username;
    state.isAuth = true;
}

/**
 * Handles login button click event.
 */
function handleLogin() {

    // Add a check property to the session, so we can recall sign-in method upon redirect with authorization code.
    // authorization code grant type flow
    sessionStorage.setItem("isInitLogin", "true");
    auth.signIn()
        .then(function (response) {
            // Perform any actions you after successful sign in.
        })
        .catch(function (error) {
            // Handle sign in error.
        });
}

/**
 * Handles logout button click event.
 */
function handleLogout() {

    auth.signOut()
        .then(function (response) {
            state.isAuth = false;
            updateView();
        })
        .catch(function (error) {
            // Handle sign out error.
        });
}

if (authConfig.clientID === "") {
    document.getElementById("missing-config").style.display = "block";
} else {
    // Check if the page redirected by the sign-in method with authorization code, if it is recall sing-in method to
    // continue the sign-in flow
    if (JSON.parse(sessionStorage.getItem("isInitLogin"))) {

        auth.signIn()
            .then(function (response) {

                setAuthenticatedState();

                sessionStorage.setItem("isInitLogin", "false");

                updateView();
            });

    } else {

        if (sessionStorage.getItem("username")) {

            state.displayName = sessionStorage.getItem("display_name");
            state.email = JSON.parse(sessionStorage.getItem("email")) ?
                JSON.parse(sessionStorage.getItem("email"))[0] : "";
            state.username = sessionStorage.getItem("username");
            state.isAuth = true;

            updateView();
        } else {
            updateView();
        }
    }
}
