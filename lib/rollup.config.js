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

import commonjs from "@rollup/plugin-commonjs";
import eslint from "@rollup/plugin-eslint";
import json from "@rollup/plugin-json";
import resolve from "@rollup/plugin-node-resolve";
import replace from "@rollup/plugin-replace";
import analyze from "rollup-plugin-analyzer";
import autoExternal from "rollup-plugin-auto-external";
import { terser } from "rollup-plugin-terser";
import typescript from "rollup-plugin-typescript2";
import pkg from "./package.json";

/**
 * UMD bundle type.
 *
 * @constant
 * @type {string}
 * @default
 */
const UMD_BUNDLE = "umd";

/**
 * ESM bundle type.
 *
 * @constant
 * @type {string}
 * @default
 */
const ESM_BUNDLE = "esm";

/**
 * The global variable to be used in UMD and IIFE bundles.
 *
 * @constant
 * @type {string}
 * @default
 */
const GLOBAL_VARIABLE = "AsgardeoAuth";

/**
 * Production environment.
 *
 * @constant
 * @type {string}
 * @default
 */
const PRODUCTION = "production";

/**
 * Development environment.
 *
 * @constant
 * @type {string}
 * @default
 */
const DEVELOPMENT = "development";

/**
 * This returns the name of the bundle file.
 *
 * @param {UMD_BUNDLE | ESM_BUNDLE | BROWSER_BUNDLE} bundleType - Specifies the type of the bundle.
 *
 * @return {string} The name of the output file.
 */
const resolveFileName = (bundleType) => {
    switch (bundleType) {
        case UMD_BUNDLE:
            return pkg.main;
        case ESM_BUNDLE:
            return pkg.module;
        default:
            return pkg.main;
    }
};

/**
 * This generates a rollup config object.
 *
 * @param {UMD_BUNDLE | ESM_BUNDLE} bundleType - Specifies the type of the bundle.
 * @param {boolean} polyfill - Specifies if the bundle should be polyfilled or not.
 * @param {PRODUCTION | DEVELOPMENT} env - Specifies if the bundle is for production or development.
 *
 * @return Rollup config object.
 */
const generateConfig = (bundleType, env) => {
    if (!env) {
        env = PRODUCTION;
    }

    const fileName = resolveFileName(bundleType);

    const config = {
        input: "src/index.ts",
        output: {
            file: fileName,
            format: bundleType,
            sourcemap: true
        },
        plugins: [
            resolve({
                browser: true,
                preferBuiltins: true
            }),
            commonjs(),
            eslint(),
            json(),
            typescript(),
            replace({
                preventAssignment: true,
                "process.env.NODE_ENV":
                    env === PRODUCTION ? JSON.stringify("production") : JSON.stringify("development")
            })
        ]
    };

    if (bundleType === UMD_BUNDLE) {
        config.output.name = GLOBAL_VARIABLE;
    }

    if (env === DEVELOPMENT) {
        config.plugins.push(analyze());
    } else {
        config.plugins.push(terser());
        // To avoid `Missing shims` and `Missing global variable` warnings.
        if (bundleType !== UMD_BUNDLE) {
            config.plugins.push(
                autoExternal({
                    builtins: false,
                    dependencies: false
                })
            );
        }

        config.output.globals = {
            axios: "axios"
        };
    }

    return config;
};

export default [generateConfig(ESM_BUNDLE, process.env.NODE_ENV), generateConfig(UMD_BUNDLE, process.env.NODE_ENV)];
