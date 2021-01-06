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

import React, { useEffect, useState } from "react";
import * as ReactDOM from "react-dom";
import ReactJson from "react-json-view";
import "./app.css";
import PRODUCT_LOGOS from "./images/asgardeo-logo.png";
import REACT_LOGO from "./images/react-logo.png";
import JS_LOGO from "./images/js-logo.png";
import FOOTER_LOGOS from "./images/footer.png";
// Import Asgardeo Auth JS SDK
import { Hooks, IdentityClient } from "@asgardio/oidc-js";
import * as authConfig from "./config.json";

const authClient = IdentityClient.getInstance();

const App = () => {

    const [ authenticateState, setAuthenticateState ] = useState({});
    const [ isAuth, setIsAuth ] = useState(null);

    authClient.on(Hooks.SignIn, (response) => {
        authClient.getDecodedIDToken().then((idToken) => {
            setIsAuth(true);
            sessionStorage.setItem("isInitLogin", "false");

            setAuthenticateState({
                ...authenticateState,
                displayName: response.displayName,
                email: JSON.parse(response.email) ? JSON.parse(response.email)[0] : "",
                decodedIdToken: idToken,
                username: response.username
            });
    
            sessionStorage.setItem("decodedIdToken", JSON.stringify(idToken));
        });
    });

    authClient.on(Hooks.SignOut, () => {
        setIsAuth(false);
        sessionStorage.setItem("isInitLogin", "false");
    });

    const handleLogin = () => {
        // Add a check property to the session, so we can recall sign-in method upon redirect with authorization code.
        // authorization code grant type flow
        sessionStorage.setItem("isInitLogin", "true");
        authClient.signIn();
    };

    const handleLogout = () => {
        authClient.signOut();
    };

    useEffect(() => {

        authClient.initialize(authConfig.default);

        // Check if the page redirected by the sign-in method with authorization code, if it is recall sing-in method to
        // continue the sign-in flow
        if ( JSON.parse(sessionStorage.getItem("isInitLogin")) ) {

            authClient.signIn();

        } else {

            if ( sessionStorage.getItem("username") ) {

                setAuthenticateState({
                    ...authenticateState,
                    displayName: sessionStorage.getItem("display_name"),
                    email: JSON.parse(sessionStorage.getItem("email")) ?
                        JSON.parse(sessionStorage.getItem("email"))[0] : "",
                    decodedIdToken: JSON.parse(sessionStorage.getItem("decodedIdToken")),
                    username: sessionStorage.getItem("username")
                });

                setIsAuth(true);
            }
        }
  
    }, []);

    return (
        <>
            <img src={ PRODUCT_LOGOS } className="logo-image" />
            <div className="container">
                { authConfig.default.clientID === "" ?
                    <div className="content">
                        <h2>You need to update the Client ID to proceed.</h2>
                        <p>Please open "src/config.json" file using an editor, and update the <code>clientID</code> value with the registered app clientID.</p>
                        <p>Visit repo <a href="https://github.com/asgardeo/asgardeo-js-oidc-sdk/tree/master/samples/react-js-app">README</a> for more details.</p>
                    </div>
                : 
                   <>
                        <div className="header-title">
                            <h1>
                                Javascript Based React SPA Authentication Sample <br /> (OIDC - Authorization Code Grant)
                            </h1>
                        </div>
                        <div className="content">
                            { isAuth === true &&
                                <>
                                    <h3>Decoded ID Token data</h3>
                                    <div className="id-token">
                                        <ReactJson src={ authenticateState.decodedIdToken } theme="monokai" />
                                    </div>
                                    <button className="btn primary" onClick={ handleLogout }>Logout</button>
                            
                                </>
                            }
                            { isAuth === false &&
                                <>

                                    <div className="home-image">
                                        <img src={ JS_LOGO } className="js-logo-image logo" />
                                        <span className="logo-plus">+</span>
                                        <img src={ REACT_LOGO } className="react-logo-image logo" />
                                    </div>
                                    <h3>
                                        Sample demo to showcase how to authenticate a simple client side application using <b>Asgardeo</b> with the <a href="https://github.com/asgardeo/asgardeo-js-oidc-sdk" 
                                            target="_blank">Asgardeo Auth JS SDK</a>
                                    </h3>
                                    <button className="btn primary" onClick={ handleLogin }>Login</button>
                                
                                </>
                            }
                        </div>
                    </>
                }
            </div>

            <img src={ FOOTER_LOGOS } className="footer-image" />
        </>
    );

}

ReactDOM.render( (<App />), document.getElementById("root") );
