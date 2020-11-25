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

import { DEFAULT_EXTENSIONS } from "@babel/core";
import babel from "@rollup/plugin-babel";
import commonjs from "@rollup/plugin-commonjs";
import eslint from "@rollup/plugin-eslint";
import resolve from "@rollup/plugin-node-resolve";
import analyze from "rollup-plugin-analyzer"
import injectProcessEnv from "rollup-plugin-inject-process-env";
import sourcemaps from "rollup-plugin-sourcemaps";
import { terser } from "rollup-plugin-terser";
import typescript from "rollup-plugin-typescript2";
import workerLoader  from "rollup-plugin-web-worker-loader";
import pkg from "./package.json";

export default [
    {
        input: "src/index.ts",
        output: {
            file: pkg.module,
            format: "esm"
        },
        plugins: [
            resolve({
                browser: true,
                preferBuiltins: true
            }),
            commonjs(),
            injectProcessEnv({
                NODE_ENV: "production"
            }),
            eslint(),
            typescript(),
            workerLoader({
                extensions: [".ts"],
                sourcemap: false,
                targetPlatform: "browser"
            }),
            terser(),
            analyze({ limit: 10 }),
            //sourcemaps()
        ]
    },

    {
        input: "src/index-polyfill.ts",
        output: {
            file: pkg.module.split("/").shift() + "/polyfilled/" + pkg.module.split("/").pop(),
            format: "esm"
        },
        plugins: [
            resolve({
                browser: true,
                preferBuiltins: true
            }),
            commonjs(),
            injectProcessEnv({
                NODE_ENV: "production"
            }),
            eslint(),
            typescript(),
            workerLoader({
                extensions: [ ".ts" ],
                sourcemap: false,
                targetPlatform: "browser"
            }),
            babel({
                babelHelpers: "runtime",
                extensions: [
                    ...DEFAULT_EXTENSIONS,
                    ".ts"
                ]
            }),
            terser(),
            analyze({ limit: 10 }),
            //sourcemaps()
        ]
    },
    {
        input: "src/index-polyfill.ts",
        output: {
            file: pkg.main.split("/").shift() + "/polyfilled/" + pkg.main.split("/").pop(),
            format: "umd",
            name: "AsgardioOIDC"
        },
        plugins: [
            resolve({
                browser: true,
                preferBuiltins: true
            }),
            commonjs(),
            eslint(),
            typescript(),
            workerLoader({
                extensions: [ ".ts" ],
                sourcemap: false,
                targetPlatform: "browser"
            }),
            babel({
                babelHelpers: "runtime",
                extensions: [
                    ...DEFAULT_EXTENSIONS,
                    ".ts",
                    ".tsx"
                ]
            }),
            terser()
        ]
    },
    {
        input: "src/index.ts",
        output: {
            file: pkg.main,
            format: "umd",
            name: "AsgardioOIDC"
        },
        plugins: [
            resolve({
                browser: true,
                preferBuiltins: true
            }),
            commonjs(),
            eslint(),
            typescript(),
            workerLoader({
                extensions: [ ".ts" ],
                sourcemap: false,
                targetPlatform: "browser"
            }),
            terser()
        ]
    },
    {
        input: "src/index.ts",
        output: {
            file: "dist/asgardio-oidc.production.min.js",
            format: "iife",
            name: "AsgardioOIDC"
        },
        plugins: [
            resolve({
                browser: true,
                preferBuiltins: true
            }),
            commonjs(),
            eslint(),
            typescript(),
            workerLoader({
                extensions: [ ".ts" ],
                sourcemap: false,
                targetPlatform: "browser"
            }),
            terser({
                output: {
                    comments: false
                }
            })
        ]
    },
    {
        input: "src/index-polyfill.ts",
        output: {
            file: "dist/polyfilled/asgardio-oidc.production.min.js",
            format: "iife",
            name: "AsgardioOIDC"
        },
        plugins: [
            resolve({
                browser: true,
                preferBuiltins: true
            }),
            commonjs(),
            eslint(),
            typescript(),
            workerLoader({
                extensions: [ ".ts" ],
                sourcemap: false,
                targetPlatform: "browser"
            }),
            babel({
                babelHelpers: "runtime",
                extensions: [
                    ...DEFAULT_EXTENSIONS,
                    ".ts",
                    ".tsx"
                ]
            }),
            terser({
                output: {
                    comments: false
                }
            })
        ]
    }
];
