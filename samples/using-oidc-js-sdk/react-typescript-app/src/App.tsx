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

import React, { FunctionComponent, ReactElement, useEffect, useState } from "react";
import "./App.css";
import ReactLogo from "./images/react-logo.png";
import JavascriptLogo from "./images/js-logo.png";
import FooterLogo from "./images/footer.png";
import { default as authConfig } from "./config.json";
import { IdentityClient, ConfigInterface, WebWorkerConfigInterface, Hooks, UserInfo } from "@asgardio/oidc-js";

/**
 * SDK Client instance.
 * @type {IdentityClient}
 */
const auth: IdentityClient = IdentityClient.getInstance();

/**
 * Main App component.
 *
 * @return {React.ReactElement}
 */
export const App: FunctionComponent<{}> = (): ReactElement => {

    const [ authenticatedUser, setAuthenticatedUser ] = useState<UserInfo>(undefined);
    const [ isAuth, setIsAuth ] = useState<boolean>(false);

    /**
     * Initialize the SDK & register Sign in and Sign out hooks.
     */
    useEffect(() => {

        const config: ConfigInterface | WebWorkerConfigInterface = authConfig as (ConfigInterface | WebWorkerConfigInterface);

        // Initialize the client with the config object.
        auth.initialize(config)
            .then((response: boolean) => {
                // Successfully initialized the SDK client.
            })
            .catch((error: any) => {
                // Handle the error occurred while initializing the SDK client.
            });

        auth.on(Hooks.SignIn, (response: UserInfo) => {
            setIsAuth(true);
            setAuthenticatedUser(response);
            sessionStorage.setItem("isInitLogin", "true");
        });

        auth.on(Hooks.SignOut, () => {
            setIsAuth(false);
            sessionStorage.setItem("isInitLogin", "false");
        });
    }, []);

    /**
     * Check if the page redirected by the sign-in method with authorization code,
     * if it is recall sing-in method to continue the sign-in flow
     */
    useEffect(() => {

        if (JSON.parse(sessionStorage.getItem("isInitLogin"))) {

            auth.signIn();
        } else {

            if (sessionStorage.getItem("username")) {

                setAuthenticatedUser({
                    ...authenticatedUser,
                    displayName: sessionStorage.getItem("display_name"),
                    email: JSON.parse(sessionStorage.getItem("email")) ?
                        JSON.parse(sessionStorage.getItem("email"))[ 0 ] : "",
                    username: sessionStorage.getItem("username")
                });

                setIsAuth(true);
            }
        }
    }, [ authenticatedUser ]);

    /**
     * Handles login button click event.
     */
    const handleLogin = (): void => {

        // Add a check property to the session, so we can recall sign-in method upon redirect with authorization code.
        // authorization code grant type flow
        sessionStorage.setItem("isInitLogin", "true");
        auth.signIn()
            .then((response) => {
                // Perform any actions you after successful sign in.
            })
            .catch((error) => {
                // Handle sign in error.
            });
    };

    /**
     * Handles logout button click event.
     */
    const handleLogout = (): void => {

        auth.signOut()
            .then((response) => {
                // Perform any actions you after successful sign out.
            })
            .catch((error) => {
                // Handle sign out error.
            });
    };

    return (
        <>
            <div className="container">
                {
                    (authConfig.clientID === "")
                        ? (
                            <div className="content">
                                <h2>You need to update the Client ID to proceed.</h2>
                                <p>
                                    Please open "src/config.json" file using an editor, and update
                                    the <code>clientID</code> value with the registered app clientID.
                                </p>
                                <p>Visit repo <a href="https://github.com/asgardeo/asgardio-js-oidc-sdk/tree/master/samples/using-oidc-js-sdk/react-typescript-app">README</a> for more details.</p>
                            </div>
                        )
                        : (isAuth && authenticatedUser)
                        ? (
                            <>
                                <div className="header-title">
                                    <h1>
                                        Javascript Based React SPA Authentication Sample <br/> (OIDC - Authorization
                                        Code
                                        Grant)
                                    </h1>
                                </div>
                                <div className="content">
                                    <h3>Below are the basic details retrieves from the server on a successful
                                        login.</h3>
                                    <div>
                                        <ul className="details">
                                            {
                                                authenticatedUser.displayName && (
                                                    <li><b>Name:</b> { authenticatedUser.displayName }</li>
                                                )
                                            }
                                            {
                                                authenticatedUser.username && (
                                                    <li><b>Username:</b> { authenticatedUser.username }</li>
                                                )
                                            }
                                            {
                                                authenticatedUser.email && authenticatedUser.email !== "null" && (
                                                    <li><b>Email:</b> { authenticatedUser.email }</li>
                                                )
                                            }
                                        </ul>
                                    </div>
                                    <button className="btn primary" onClick={ () => handleLogout() }>Logout</button>
                                </div>
                            </>
                        )
                        : (
                            <>
                                <div className="header-title">
                                    <h1>
                                        Javascript Based React SPA Authentication Sample <br/> (OIDC - Authorization
                                        Code
                                        Grant)
                                    </h1>
                                </div>
                                <div className="content">
                                    <div className="home-image">
                                        <img src={ JavascriptLogo } alt="js-logo" className="js-logo-image logo"/>
                                        <span className="logo-plus">+</span>
                                        <img src={ ReactLogo } alt="react-logo" className="react-logo-image logo"/>
                                    </div>
                                    <h3>
                                        Sample demo to showcase how to authenticate a simple client side application
                                        using <b>WSO2 Identity Server</b> with the <a
                                        href="https://github.com/asgardeo/asgardio-js-oidc-sdk"
                                        target="_blank" rel="noreferrer">Asgardio OIDC JS SDK</a>
                                    </h3>
                                    <button className="btn primary" onClick={ () => handleLogin() }>Login</button>
                                </div>
                            </>
                        )
                }
            </div>

            <img src={ FooterLogo } className="footer-image" alt="footer-logo"/>
        </>
    );
};
