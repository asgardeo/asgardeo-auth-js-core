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

import typescript from '@rollup/plugin-typescript';
import resolve from '@rollup/plugin-node-resolve';
import commonjs from '@rollup/plugin-commonjs';
import json from "@rollup/plugin-json";
import babel from '@rollup/plugin-babel';
import { eslint } from "rollup-plugin-eslint";
import webWorkerLoader from 'rollup-plugin-web-worker-loader';

export default {
    input: "src/index.ts",
    output: {
        format: "cjs",
        dir: "dist"
    },
    plugins: [ resolve(), typescript(), commonjs(), json(), babel(), eslint(), webWorkerLoader() ]
};
