/**
 * Copyright (c) 2019, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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
 *
 */

import axios from "axios";
import {
    HttpError,
    HttpRequestConfig,
    HttpResponse
} from "../..";
import { staticDecorator } from "../helpers";
import {
    HttpClientInstance,
    HttpClientInterface,
    HttpClientStatic
} from "../models";

/**
 * An Http Http client to perform Http requests.
 *
 * @remarks
 * Typescript doesn't support static functions in interfaces. Therefore,
 * a decorator i.e `staticDecorator` was written to add static support.
 * Follow {@link https://github.com/Microsoft/TypeScript/issues/13462}
 * for more info.
 *
 * @example
 * Example usage.
 * ```
 *
 * const httpClient = HttpClient.getInstance();
 * httpClient.init(true, onRequestStart, onRequestSuccess, onRequestError, onRequestFinish);
 * ```
 */
@staticDecorator<HttpClientStatic<HttpClientInstance>>()
export class HttpClient implements HttpClientInterface<HttpRequestConfig, HttpResponse, HttpError> {

    private static axiosInstance: HttpClientInstance;
    private static clientInstance: HttpClient;
    private static isHandlerEnabled: boolean;
    private attachToken: (request: HttpRequestConfig) => void;
    private requestStartCallback: (request: HttpRequestConfig) => void;
    private requestSuccessCallback: (response: HttpResponse) => void;
    private requestErrorCallback: (error: HttpError) => void;
    private requestFinishCallback: () => void;
    private static readonly DEFAULT_HANDLER_DISABLE_TIMEOUT: number = 1000;

    /**
     * Private constructor to avoid object instantiation from outside
     * the class.
     *
     * @hideconstructor
     */
    private constructor() {
        this.init = this.init.bind(this);
    }

    /**
     * Returns an aggregated instance of type `HttpInstance` of `HttpClient`.
     *
     * @return {any}
     */
    public static getInstance(): HttpClientInstance {
        if (this.axiosInstance) {
            return this.axiosInstance;
        }

        this.axiosInstance = axios.create({
            withCredentials: true
        });

        if (!this.clientInstance) {
            this.clientInstance = new HttpClient();
        }

        // Register request interceptor
        this.axiosInstance.interceptors.request.use(
            (request) => this.clientInstance.requestHandler(request)
        );

        // Register response interceptor
        this.axiosInstance.interceptors.response.use(
            (response) => this.clientInstance.successHandler(response),
            (error) => this.clientInstance.errorHandler(error)
        );

        // Add the missing helper methods from axios
        this.axiosInstance.all = axios.all;
        this.axiosInstance.spread = axios.spread;

        // Add the init method from the `HttpClient` instance.
        this.axiosInstance.init = this.clientInstance.init;

        // Add the handler enabling & disabling methods to the instance.
        this.axiosInstance.enableHandler = this.clientInstance.enableHandler;
        this.axiosInstance.disableHandler = this.clientInstance.disableHandler;
        this.axiosInstance.disableHandlerWithTimeout = this.clientInstance.disableHandlerWithTimeout;

        return this.axiosInstance;
    }

    /**
     * Intercepts all the requests.
     * If the `isHandlerEnabled` flag is set to true, fires the `requestStartCallback`
     * and retrieves the access token from the server and attaches it to the request.
     * Else, just returns the original request.
     *
     * @param {HttpRequestConfig} request - Original request.
     * @return {HttpRequestConfig}
     */
    public requestHandler(request: HttpRequestConfig): HttpRequestConfig {
        this.attachToken(request);

        if (HttpClient.isHandlerEnabled) {
            if (this.requestStartCallback && typeof this.requestStartCallback === "function") {
                this.requestStartCallback(request);
            }
        }
        return request;
    }

    /**
     * Handles response errors.
     * If the `isHandlerEnabled` flag is set to true, fires the `requestErrorCallback`
     * and the `requestFinishCallback` functions. Else, just returns the original error.
     *
     * @param {HttpError} error - Original error.
     * @return {HttpError}
     */
    public errorHandler(error: HttpError): HttpError {
        if (HttpClient.isHandlerEnabled) {
            if (this.requestErrorCallback && typeof this.requestErrorCallback === "function") {
                this.requestErrorCallback(error);
            }
            if (this.requestFinishCallback && typeof this.requestFinishCallback === "function") {
                this.requestFinishCallback();
            }
        }
        throw error;
    }

    /**
     * Handles response success.
     * If the `isHandlerEnabled` flag is set to true, fires the `requestSuccessCallback`
     * and the `requestFinishCallback` functions. Else, just returns the original response.
     *
     * @param {HttpResponse} response - Original response.
     * @return {HttpResponse}
     */
    public successHandler(response: HttpResponse): HttpResponse {
        if (HttpClient.isHandlerEnabled) {
            if (this.requestSuccessCallback && typeof this.requestSuccessCallback === "function") {
                this.requestSuccessCallback(response);
            }
            if (this.requestFinishCallback && typeof this.requestFinishCallback === "function") {
                this.requestFinishCallback();
            }
        }
        return response;
    }

    /**
     * Initializes the Http client.
     *
     * @param isHandlerEnabled - Flag to toggle handler enablement.
     * @param requestStartCallback - Callback function to be triggered on request start.
     * @param requestSuccessCallback - Callback function to be triggered on request success.
     * @param requestErrorCallback - Callback function to be triggered on request error.
     * @param requestFinishCallback - Callback function to be triggered on request error.
     */
    public init(
        isHandlerEnabled = true,
        attachToken: (request: HttpRequestConfig) => void,
        requestStartCallback: (request: HttpRequestConfig) => void,
        requestSuccessCallback: (response: HttpResponse) => void,
        requestErrorCallback: (error: HttpError) => void,
        requestFinishCallback: () => void
    ): void {
        HttpClient.isHandlerEnabled = isHandlerEnabled;

        if (this.requestStartCallback
            && this.attachToken
            && this.requestSuccessCallback
            && this.requestErrorCallback
            && this.requestFinishCallback) {
            return;
        }

        if (!this.attachToken) {
            this.attachToken = attachToken;
        }
        if (!this.requestStartCallback) {
            this.requestStartCallback = requestStartCallback;
        }
        if (!this.requestSuccessCallback) {
            this.requestSuccessCallback = requestSuccessCallback;
        }
        if (!this.requestErrorCallback) {
            this.requestErrorCallback = requestErrorCallback;
        }
        if (!this.requestFinishCallback) {
            this.requestFinishCallback = requestFinishCallback;
        }
    }

    /**
     * Enables the handler.
     */
    public enableHandler(): void {
        HttpClient.isHandlerEnabled = true;
    }

    /**
     * Disables the handler.
     */
    public disableHandler(): void {
        HttpClient.isHandlerEnabled = false;
    }

    /**
     * Disables the handler for a given period of time.
     *
     * @param {number} timeout - Timeout in milliseconds.
     */
    public disableHandlerWithTimeout(timeout: number = HttpClient.DEFAULT_HANDLER_DISABLE_TIMEOUT): void {
        HttpClient.isHandlerEnabled = false;

        setTimeout(() => {
            HttpClient.isHandlerEnabled = true;
        }, (timeout));
    }
}
