/// <reference types="jquery" />
/// <reference path="./interfaces.ts" />


// type-checking
// import * as $ from "jquery";


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

    login: (email: string, password: string) => {
        const url = pzAPI.base_url + "/api/v1/login";
        const data = {
            email: email,
            password: password
        };
        return pzAPI.postJSON(url, data);
    },

    logout: () => {
        const url = pzAPI.base_url + "/api/v1/logout";
        return pzAPI.postJSON(url);
    },

    signup: (email: string, password: string, confirmPassword: string) => {
        const url = pzAPI.base_url + "/api/v1/user/signup";
        const data = {
            email: email,
            password: password,
            confirm_password: confirmPassword
        };
        return pzAPI.postJSON(url, data);
    },

    getCSRFToken: () => {
        const url = pzAPI.base_url + "/api/v1/csrf_token";
        return pzAPI.getJSON(url);
    },

    getEntries: () => {
        const url = pzAPI.base_url + "/api/v1/entries";
        return pzAPI.getJSON(url);
    },

    getEntriesV2: () => {
        const url = pzAPI.base_url + "/api/v2/entries";
        return pzAPI.getJSON(url);
    },

    decryptEntry: (entryId: number) => {
        const url = pzAPI.base_url + `/api/v2/entries/${entryId}`;
        return pzAPI.getJSON(url);
    },

    _createEntry: (entry: IEntryUpload, csrfToken: string) => {
        const url = pzAPI.base_url + "/api/v1/entries";
        const data = pzAPI._copyObject(entry);
        data.csrf_token = csrfToken;
        return pzAPI.postJSON(url, data);
    },

    createEntry: (entry: IEntryUpload) => {
        return pzAPI.getCSRFToken()
            .then((response) => {
                return pzAPI._createEntry(entry, response);
            });
    },

    _editEntry: (entryId: number, entry: IEntryUpload, csrfToken: string) => {
        const url = "/api/v1/entries/" + entryId;
        const data = pzAPI._copyObject(entry);
        data.csrf_token = csrfToken;
        return pzAPI.putJSON(url, data);
    },

    editEntry: (entryId: number, entry: IEntryUpload) => {
        return pzAPI.getCSRFToken()
            .then((response) => {
                return pzAPI._editEntry(entryId, entry, response);
            });
    },

    _deleteEntry: (csrfToken: string, entryId: number) => {
        const url = "/api/v1/entries/" + entryId;
        return pzAPI.deleteJSON(url, { "csrf_token": csrfToken });
    },

    deleteEntry: (entryId: number) => {
        return pzAPI.getCSRFToken()
            .then((response) => {
                return pzAPI._deleteEntry(response, entryId);
            });
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

// export { pzAPI };
