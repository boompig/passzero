// provided externally via CDN
declare let $: any;

$.postJSON = function(url, data) {
    data = data || {};
    return $.ajax({
        url: url,
        data: JSON.stringify(data),
        method: "POST",
        contentType: "application/json",
        dataType: "json"
    });
};

$.putJSON = function(url, data) {
    data = data || {};
    return $.ajax({
        url: url,
        data: JSON.stringify(data),
        method: "PUT",
        contentType: "application/json",
        dataType: "json"
    });
};


$.getJSON = function(url, data) {
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
};

$.deleteJSON = function(url, data) {
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
};


const pzAPI = {
    base_url: window.location.protocol + "//" + window.location.host,

    _copyObject: function(o: any): any {
        let newObj = {};
        for (let k in o) {
            newObj[k] = o[k];
        }
        return newObj;
    },

    login: function(email, password) {
        const url = pzAPI.base_url + "/api/login";
        const data = {
            email: email,
            password: password
        };
        return $.postJSON(url, data);
    },

    logout: function() {
        const url = pzAPI.base_url + "/api/logout";
        return $.postJSON(url);
    },

    signup: function(email: string, password: string, confirm_password: string) {
        const url = pzAPI.base_url + "/api/signup";
        const data = {
            email: email,
            password: password,
            confirm_password: confirm_password
        };
        return $.postJSON(url, data);
    },

    getCSRFToken: function(): Promise<string> {
        const url = pzAPI.base_url + "/api/csrf_token";
        return $.getJSON(url);
    },

    getEntries: function(): Promise<Array<any>> {
        const url = pzAPI.base_url + "/api/v1/entries";
        return $.getJSON(url);
    },

    getEntriesV2: function(): Promise<Array<any>> {
        const url = pzAPI.base_url + "/api/v2/entries";
        return $.getJSON(url);
    },

    _createEntry: function(entry, csrf_token: string) {
        const url = pzAPI.base_url + "/api/entries/new";
        let data = pzAPI._copyObject(entry);
        data.csrf_token = csrf_token;
        return $.postJSON(url, data);
    },

    createEntry: function(entry): Promise<any> {
        return pzAPI.getCSRFToken()
        .then(function(response) {
            return pzAPI._createEntry(entry, response);
        });
    },

    _editEntry: function(entry_id: number, entry, csrf_token: string): Promise<any> {
        const url = "/api/entries/" + entry_id;
        let data = pzAPI._copyObject(entry);
        data.csrf_token = csrf_token;
        return $.postJSON(url, data);
    },
    editEntry: function(entry_id: number, entry): Promise<any> {
        return pzAPI.getCSRFToken()
        .then(function(response) {
            return pzAPI._editEntry(entry_id, entry, response);
        });
    },
    _deleteEntry: function(csrf_token: string, entry_id: number) {
        const url = "/api/entries/" + entry_id;
        return $.deleteJSON(url, { "csrf_token": csrf_token });
    },
    deleteEntry: function(entry_id) {
        return pzAPI.getCSRFToken()
        .then(function(response) {
            return pzAPI._deleteEntry(response, entry_id);
        });
    },
    _recoverAccount: function(email: string, csrf_token: string): Promise<any> {
        const url = "/api/recover";
        const data = { "csrf_token": csrf_token, "email": email };
        return $.postJSON(url, data);
    },
    recoverAccount: function(email: string): Promise<any> {
        return pzAPI.getCSRFToken()
        .then(function(response) {
            return pzAPI._recoverAccount(email, response);
        });
    },
    _recoverAccountConfirm: function(csrfToken: string,
        token: string,
        password: string,
        confirmPassword: string) {
        const url = "/api/v1/user/recover/confirm";
        const data = {
            "token": token,
            "password": password,
            "confirm_password": confirmPassword
        };
        return $.postJSON(url, data);
    },
    recoverAccountConfirm: function(token: string, password: string, confirmPassword: string) {
        return pzAPI.getCSRFToken()
        .then(function(response) {
            return pzAPI._recoverAccountConfirm(response, token, password, confirmPassword);
        });
    },
    _changeAccountPassword: function(csrfToken: string,
        oldPassword: string,
        newPassword: string,
        confirmNewPassword: string) {
        const url = "/api/v1/user/password";
        const data = {
            "csrf_token": csrfToken,
            "old_password": oldPassword,
            "new_password": newPassword,
            "confirm_new_password": confirmNewPassword
        };
        return $.putJSON(url, data);
    },
    changeAccountPassword: function(oldPassword: string, newPassword: string, confirmNewPassword: string) {
        return pzAPI.getCSRFToken()
        .then(function(response) {
            return pzAPI._changeAccountPassword(response, oldPassword, newPassword, confirmNewPassword);
        });
    },
    _updateUserPreferences: function(csrfToken: string, prefs: any) {
        const url = "/api/v1/user/preferences";
        const data = pzAPI._copyObject(prefs);
        data.csrf_token = csrfToken;
        return $.putJSON(url, data);
    },
    updateUserPreferences: function(prefs: any): Promise<any> {
        return pzAPI.getCSRFToken()
        .then(function(response) {
            return pzAPI._updateUserPreferences(response, prefs);
        });
    },
    _nukeEntries: function(csrf_token: string): Promise<any> {
        const url = "/api/v1/entries/nuclear";
        return $.postJSON(url);
    },
    nukeEntries: function(): Promise<any> {
        return pzAPI.getCSRFToken()
        .then(function(response) {
            return pzAPI._nukeEntries(response);
        });
    }
};
