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

    _recoverAccount: (email: string, csrfToken: string) => {
        const url = "/api/v1/user/recover";
        const data = { "csrf_token": csrfToken, "email": email };
        return pzAPI.postJSON(url, data);
    },

    recoverAccount: (email: string) => {
        return pzAPI.getCSRFToken()
            .then((response) => {
                return pzAPI._recoverAccount(email, response);
            });
    },

    _recoverAccountConfirm: (csrfToken: string, token: string, password: string, confirmPassword: string) => {
        const url = "/api/v1/user/recover/confirm";
        const data = {
            "token": token,
            "password": password,
            "confirm_password": confirmPassword
        };
        return pzAPI.postJSON(url, data);
    },

    recoverAccountConfirm: (token: string, password: string, confirmPassword: string) => {
        return pzAPI.getCSRFToken()
            .then((response) => {
                return pzAPI._recoverAccountConfirm(response, token, password, confirmPassword);
            });
    },

    _changeAccountPassword: (csrfToken: string, oldPassword: string, newPassword: string, confirmNewPassword: string) => {
        const url = "/api/v1/user/password";
        const data = {
            "csrf_token": csrfToken,
            "old_password": oldPassword,
            "new_password": newPassword,
            "confirm_new_password": confirmNewPassword
        };
        return pzAPI.putJSON(url, data);
    },

    changeAccountPassword: (oldPassword: string, newPassword: string, confirmNewPassword: string) => {
        return pzAPI.getCSRFToken()
            .then((response: string) => {
                return pzAPI._changeAccountPassword(response, oldPassword, newPassword, confirmNewPassword);
            });
    },

    _updateUserPreferences: (csrfToken: string, prefs: any) => {
        const url = "/api/v1/user/preferences";
        const data = pzAPI._copyObject(prefs);
        data.csrf_token = csrfToken;
        return pzAPI.putJSON(url, data);
    },

    updateUserPreferences: (prefs: any) => {
        return pzAPI.getCSRFToken()
            .then((response) => {
                return pzAPI._updateUserPreferences(response, prefs);
            });
    },

    _deleteUser: (csrfToken: string, password: string) => {
        const url = "/api/v1/user";
        const data = {
            "csrf_token": csrfToken,
            "password": password
        };
        return pzAPI.deleteJSON(url, data);
    },

    deleteUser: (password: string) => {
        return pzAPI.getCSRFToken()
            .then((response) => {
                return pzAPI._deleteUser(response, password);
            });
    },

    _deleteAllEntries: (csrfToken: string) => {
        const url = "/api/v1/entries";
        return pzAPI.deleteJSON(url, { "csrf_token": csrfToken });
    },

    deleteAllEntries: () => {
        return pzAPI.getCSRFToken()
            .then((response) => {
                return pzAPI._deleteAllEntries(response);
            });
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
