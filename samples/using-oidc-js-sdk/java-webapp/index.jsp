<%
    session.setAttribute("authCode", request.getParameter("code"));
    session.setAttribute("sessionState", request.getParameter("session_state"));
%>

<!DOCTYPE html>
<html lang="en">
    <head>
        <meta charset="UTF-8" />
        <meta name="viewport" content="width=device-width, initial-scale=1.0" />
        <title>Asgardio OIDC SDK - Sample</title>
        <style>
            body {
                min-height: 100vh;
                display: flex;
                justify-content: center;
                align-items: center;
                background-color: #212121;
                color: white;
                font-family: "Courier New", Courier, monospace;
            }

            #greeting {
                font-size: 2em;
                margin: 1em;
                text-align: center;
            }

            .details {
                margin: 1em;
            }

            .details div {
                margin-bottom: 1em;
                font-size: 1em;
                width: 100%;
                overflow: hidden;
                overflow-wrap: break-word;
            }

            .menu {
                display: flex;
                justify-content: space-between;
            }

            .wrapper {
                display: flex;
                flex-direction: column;
                justify-content: flex-start;
                min-height: 320px;
                width: 500px;
                border-radius: 5px;
                padding: 2em;
                background-color: #1d1c21;
            }

            .menu button {
                padding: 1em;
                border: none;
                color: white;
                background-color: #3d4444;
                cursor: pointer;
                border-radius: 5px;
                font-family: "Segoe UI", Tahoma, Geneva, Verdana, sans-serif;
            }
        </style>
    </head>
    <body>
        <div class="wrapper">
            <div class="menu">
                <button onclick="signIn()">Sign In</button>
                <button onclick="signOut()">Sign Out</button>
                <button onclick="getUserProfile()">Get user info</button>
            </div>
            <div id="greeting"></div>
            <div class="details">
                <div id="email"></div>
                <div id="lastName"></div>
                <div id="roles"></div>
            </div>
        </div>
    </body>
    <script src="https://cdn.jsdelivr.net/npm/axios@0.20.0/dist/axios.min.js"></script>
    <!-- This script tag is only meant for development -->
    <script src="assets/asgardio-oidc.production.min.js"></script>
    <!-- In production, use this script tag: -->
    <!-- <script src="https://unpkg.com/@asgardio/oidc-js@0.1.26/dist/asgardio-oidc.production.min.js.js"></script> -->

    <script>
        var serverOrigin = "https://localhost:9443";
        var isAuthenticated = false;

        // Instantiate the `IdentityClient` singleton
        var auth = AsgardioAuth.IdentityClient.getInstance();

        axios.get("auth").then((response)=>{
            // Initialize the client
            auth.initialize({
                baseUrls: [ serverOrigin ],
                signInRedirectURL: origin + "/java-webapp",
                clientID: "client-id",
                serverOrigin: serverOrigin,
                storage: "webWorker",
                responseMode: "form_post",
                authorizationCode: response.data.authCode,
                sessionState: response.data.sessionState
            });

            if(response.data.authCode){
                auth.signIn();
            }
        })

        //Sign in function
        function signIn() {
            if (isAuthenticated) {
                alert("You are already signed in. Sign out first and then sign in again.");
                return;
            }

            auth.signIn();
        }

        //Sign out function
        function signOut() {
            if (!isAuthenticated) {
                alert("You need to sign in first!");
                return;
            }

            auth.signOut();
        }

        //Pass the callback function to be called after signing in using the `sign-in` hook
        auth.on("sign-in", function (response) {
            document.getElementById("greeting").innerHTML = "Hello, " + response.displayName + "!";
            isAuthenticated = true;
        });

        auth.on("sign-out", function (){
            document.getElementById("greeting").innerHTML = "You have successfully signed out!";
        });

        //Get user profile function
        function getUserProfile() {
            if (!isAuthenticated) {
                alert("You need to sign in first!");
                return;
            }

            auth.httpRequest({
                url: serverOrigin + "/api/identity/user/v1.0/me",
                method: "GET",
                headers: {
                    "Access-Control-Allow-Origin": clientHost,
                    Accept: "application/json"
                }
            }).then((response) => {
                document.getElementById("email").innerHTML =
                    "<b>Email:</b> " + response.data.basic["http://wso2.org/claims/emailaddress"];
                document.getElementById("lastName").innerHTML =
                    "<b>Last name:</b> " + response.data.basic["http://wso2.org/claims/lastname"];
                document.getElementById("roles").innerHTML =
                    "<b>Role:</b> " + response.data.basic["http://wso2.org/claims/role"];
            });
        }
    </script>
</html>
