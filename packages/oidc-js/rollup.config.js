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
import json from "@rollup/plugin-json";
import resolve from "@rollup/plugin-node-resolve";
import autoExternal from "rollup-plugin-auto-external";
import { terser } from "rollup-plugin-terser";
import typescript from "rollup-plugin-typescript2";
import webWorkerLoader from "rollup-plugin-web-worker-loader";
import pkg from "./package.json";

export default [
    {
    input: "src/index.ts",
    output: {
        file: pkg.module,
        format: "esm"
    },
    plugins: [
        resolve(),
        commonjs(),
        json(),
        eslint(),
        typescript(),
        autoExternal(),
        webWorkerLoader(),
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
                comments: function (node, comment) {
                    var text = comment.value;
                    var type = comment.type;
                    if (type == "comment2") {
                        // multiline comment
                        return /@preserve/i.test(text);
                    }
                }
            }
        })
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
            resolve(),
            commonjs(),
            json(),
            eslint(),
            typescript(),
            autoExternal(),
            webWorkerLoader(),
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
                    comments: function (node, comment) {
                        var text = comment.value;
                        var type = comment.type;
                        if (type == "comment2") {
                            // multiline comment
                            return /@preserve/i.test(text);
                        }
                    }
                }
            })
        ]
    },
    {
        input: "src/index.ts",
        output: {
            file: pkg.browser,
            format: "iife",
            name: "AsgardioOIDC"
        },
        plugins: [
            resolve(),
            commonjs(),
            json(),
            eslint(),
            typescript(),
            webWorkerLoader(),
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
    }
];
