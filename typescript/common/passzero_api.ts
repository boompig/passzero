/// <reference types="jquery" />
/// <reference path="./interfaces.ts" />


// type-checking
// import * as $ from "jquery";


/**
 * API v1 and v2
 * NOTE: This is deprecated! Use API v3 from now on.
 * @deprecated
 */
const pzAPI = {
    base_url: window.location.protocol + "//" + window.location.host,

    // fill in some JSON methods I would have liked from jquery

    getJSON: (url: string, data?: any) => {
        data = data || {};
        if (Object.keys(data).length > 0) {
            url += "?" + $.param(data);
        }
        return $.ajax({
            url: url,
            method: "GET",
            contentType: "application/json",
            dataType: "json"
        });
    },

    postJSON: (url: string, data?: any) => {
        data = data || {};
        return $.ajax({
            url: url,
            data: JSON.stringify(data),
            method: "POST",
            contentType: "application/json",
            dataType: "json"
        });
    },

    putJSON: (url: string, data?: any) => {
        data = data || {};
        return $.ajax({
            url: url,
            data: JSON.stringify(data),
            method: "PUT",
            contentType: "application/json",
            dataType: "json"
        });
    },

    deleteJSON: (url: string, data?: any) => {
        data = data || {};
        if (Object.keys(data).length > 0) {
            url += "?" + $.param(data);
        }
        return $.ajax({
            url: url,
            method: "DELETE",
            contentType: "application/json",
            dataType: "json"
        });
    },

    // now start the real functions

    _copyObject: (o: any): any => {
        const newObj: any = {};
        for (const k in o) {
            newObj[k] = o[k];
        }
        return newObj;
    },

    getCSRFToken: () => {
        const url = pzAPI.base_url + "/api/v1/csrf_token";
        return pzAPI.getJSON(url);
    },
};

interface IApiKey {
    token: string;
}

class PasszeroApiv3 {
    async getJsonWithBearer(url: string, apiToken?: string) {
        const options = {
            method: "GET",
            headers: {
                "Content-Type": "application/json",
            },
        } as RequestInit;
        if (apiToken) {
            (options.headers as any).Authorization = `Bearer ${apiToken}`;
        }
        const response = await window.fetch(url, options);
        if (response.ok) {
            return response.json();
        } else {
            const text = await response.text();
            throw new Error(text);
        }
    }


    /**
     * If rawResponse is not defined then default to false
     */
    async patchJsonWithBearer(url: string, apiToken: string, data?: any, rawResponse?: boolean) {
        if (!data) {
            data = {};
        }
        if (!rawResponse) {
            rawResponse = false;
        }
        const options = {
            method: "PATCH",
            headers: {
                "Content-Type": "application/json",
                "Authorization": `Bearer ${apiToken}`
            },
            body: JSON.stringify(data),
        } as RequestInit;
        const response = await window.fetch(url, options);
        if (rawResponse) {
            return response;
        } else {
            return response.json();
        }
    }

    async getToken(): Promise<string> {
        const url = "/api/v3/token";
        return (await this.getJsonWithBearer(url)).token;
    }

    /**
     * Return the # updated
     */
    async updateEntryVersions(masterPassword: string): Promise<number> {
        if (!masterPassword) {
            throw new Error("masterPassword is a required argument");
        }
        const url = "/api/v3/entries";
        const token = await this.getToken();
        const responseJson = await this.patchJsonWithBearer(url, token, {
            "password": masterPassword
        });
        return responseJson.num_updated;
    }

}

// export { pzAPI };
