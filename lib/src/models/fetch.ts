import { OIDCProviderMetaData } from "./oidc-provider-meta-data";

export type Method =
    | "get" | "GET"
    | "delete" | "DELETE"
    | "head" | "HEAD"
    | "options" | "OPTIONS"
    | "post" | "POST"
    | "put" | "PUT"
    | "patch" | "PATCH"
    | "purge" | "PURGE"
    | "link" | "LINK"
    | "unlink" | "UNLINK";

export type FetchCredentials =
    | "omit"
    | "same-origin"
    | "include";

export type FetchRedirect =
    | "follow"
    | "error"
    | "manual";

export interface FetchRequestConfig extends RequestInit {
    method?: Method;
    url?: string;
    credentials?: FetchCredentials,
    body?: any;
    bodyUsed?: boolean,
    cache?: RequestCache,
    destination?: string,
    integrity?: string,
    mode?: RequestMode,
    redirect?: FetchRedirect,
    referrer?: string,
    referrerPolicy?: ReferrerPolicy;
}

export interface FetchResponse<T = any> extends ResponseInit {
    body: T;
    ok: boolean,
    bodyUsed?: boolean,
    redirected?: boolean,
    type: ResponseType,
    url: string;
    //TODO: Implement trailer property once the MDN docs are completed
    json(),
    text(),
    formData(),
    blob(),
    arrayBuffer();
}

export interface FetchError<T = any> extends Error {
    config: FetchRequestConfig;
    code?: string;
    request?: any;
    response?: FetchResponse<T>;
    isFetchError: boolean;
    // eslint-disable-next-line @typescript-eslint/ban-types
    toJSON: () => object;
}

export interface OIDCProviderMetaDataResponse extends FetchResponse {
    status: number,
    data?: OIDCProviderMetaData;
}
