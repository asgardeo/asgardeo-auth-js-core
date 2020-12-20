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

import { Hooks, AsgardeoSPAClient } from "@asgardio/oidc-js";
import { FunctionComponent, ReactElement, useEffect } from "react";
import { useHistory } from "react-router-dom";
import { useRecoilState, useSetRecoilState } from "recoil";
import { DASHBOARD } from "../constants";
import { authState, displayName } from "../recoil";

export const SignIn: FunctionComponent<null> = (): ReactElement => {
    const [ auth, setAuth ] = useRecoilState(authState);
    const setDisplayName = useSetRecoilState(displayName);

    const history = useHistory();

    useEffect(() => {
        if (auth) {
            history.push(DASHBOARD);
        } else {
            const auth = AsgardeoSPAClient.getInstance();
            auth.on(Hooks.SignIn, (response: any) => {
                setAuth(true);
                setDisplayName(response.displayName);
            });
            auth.signIn();
        }
    }, [ auth, history, setAuth, setDisplayName ]);

    return null;
};
