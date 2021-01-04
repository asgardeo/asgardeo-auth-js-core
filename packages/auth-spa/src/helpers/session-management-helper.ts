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

import { OP_IFRAME, PROMPT_NONE_IFRAME, RP_IFRAME, STATE } from "../constants";
import { SessionManagementHelperInterface } from "../models";

export const SessionManagementHelper = (() => {
    let _clientID: string;
    let _checkSessionEndpoint: string;
    let _sessionState: string;
    let _interval: number;
    let _redirectURL: string;
    let _authorizationEndpoint: string;

    const initialize = (
        clientID: string,
        checkSessionEndpoint: string,
        sessionState: string,
        interval: number,
        redirectURL: string,
        authorizationEndpoint: string
    ): void => {
        _clientID = clientID;
        _checkSessionEndpoint = checkSessionEndpoint;
        _sessionState = sessionState;
        _interval = interval;
        _redirectURL = redirectURL;
        _authorizationEndpoint = authorizationEndpoint;

        if (_interval > -1) {
            initiateCheckSession();
        }
    };

    const initiateCheckSession = (): void => {
        if (!_checkSessionEndpoint || !_clientID || !_redirectURL) {
            return;
        }
        function startCheckSession(
            checkSessionEndpoint: string,
            clientID: string,
            redirectURL: string,
            sessionState: string,
            interval: number
        ): void {
            function checkSession(): void {
                if (Boolean(clientID) && Boolean(sessionState)) {
                    const message = `${clientID} ${sessionState}`;
                    const opIframe: HTMLIFrameElement = document.getElementById(OP_IFRAME) as HTMLIFrameElement;
                    const win: Window = opIframe.contentWindow;
                    win.postMessage(message, checkSessionEndpoint);
                }
            }

            const opIframe: HTMLIFrameElement = document.getElementById(OP_IFRAME) as HTMLIFrameElement;
            opIframe.src = checkSessionEndpoint + "?client_id=" + clientID + "&redirect_uri=" + redirectURL;
            checkSession();

            setInterval(checkSession, interval * 1000);
        }

        const rpIFrame = document.getElementById(RP_IFRAME) as HTMLIFrameElement;
        (rpIFrame.contentWindow as any).eval(startCheckSession.toString());
        rpIFrame.contentWindow[startCheckSession.name](
            _checkSessionEndpoint,
            _clientID,
            _redirectURL,
            _sessionState,
            _interval
        );

        listenToResponseFromOPIFrame();
    };

    const getRandomPKCEChallenge = (): string => {
        const chars = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXTZabcdefghiklmnopqrstuvwxyz-_";
        const stringLength = 43;
        let randomString = "";
        for (let i = 0; i < stringLength; i++) {
            const rnum = Math.floor(Math.random() * chars.length);
            randomString += chars.substring(rnum, rnum + 1);
        }
        return randomString;
    };

    const listenToResponseFromOPIFrame = (): void => {
        const rpIFrame = document.getElementById(RP_IFRAME) as HTMLIFrameElement;

        function receiveMessage(e) {
            const targetOrigin = _checkSessionEndpoint;

            if (!targetOrigin || targetOrigin?.indexOf(e.origin) < 0) {
                return;
            }

            if (e.data === "unchanged") {
                // [RP] session state has not changed
            } else {
                // [RP] session state has changed. Sending prompt=none request...
                const promptNoneIFrame: HTMLIFrameElement = rpIFrame.contentDocument.getElementById(
                    PROMPT_NONE_IFRAME
                ) as HTMLIFrameElement;
                promptNoneIFrame.src =
                    _authorizationEndpoint +
                    "?response_type=code" +
                    "&client_id=" +
                    _clientID +
                    "&scope=openid" +
                    "&redirect_uri=" +
                    _redirectURL +
                    "&state=" +
                    STATE +
                    "&prompt=none" +
                    "&code_challenge_method=S256&code_challenge=" +
                    getRandomPKCEChallenge();
            }
        }

        rpIFrame.contentWindow.addEventListener("message", receiveMessage, false);
    };

    const receivePromptNoneResponse = async (
        signOut: () => Promise<string>,
        setSessionState: (sessionState: string) => Promise<void>
    ): Promise<boolean> => {
        if (_interval > -1) {
            const state = new URL(window.location.href).searchParams.get("state");
            if (state !== null && state === STATE) {
                // Prompt none response.
                const code = new URL(window.location.href).searchParams.get("code");

                if (code !== null && code.length !== 0) {
                    const newSessionState = new URL(window.location.href).searchParams.get("session_state");

                    await setSessionState(newSessionState);

                    window.stop();
                } else {
                    window.top.location.href = await signOut();
                    window.stop();

                    return true;
                }
            }
        }

        return false;
    };

    return (): SessionManagementHelperInterface => {
        const opIFrame = document.createElement("iframe");
        opIFrame.setAttribute("id", OP_IFRAME);
        opIFrame.style.display = "none";

        let rpIFrame = document.createElement("iframe");
        rpIFrame.setAttribute("id", RP_IFRAME);
        rpIFrame.style.display = "none";

        const promptNoneIFrame = document.createElement("iframe");
        promptNoneIFrame.setAttribute("id", PROMPT_NONE_IFRAME);
        promptNoneIFrame.style.display = "none";

        document.body.appendChild(rpIFrame);
        rpIFrame = document.getElementById(RP_IFRAME) as HTMLIFrameElement;
        rpIFrame.contentDocument.body.appendChild(opIFrame);
        rpIFrame.contentDocument.body.appendChild(promptNoneIFrame);

        return {
            initialize,
            receivePromptNoneResponse
        };
    };
})();
