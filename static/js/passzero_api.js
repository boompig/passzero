var require = require || null;
var module = module || null;
if (require) {
    var $ = require("jquery");
}

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

var pzAPI = {
    base_url: "https://" + window.location.host,

    _copyObject: function(o) {
        var newObj = {};
        for (var k in o) {
            newObj[k] = o[k];
        }
        return newObj;
    },

    login: function(email, password) {
        var url = pzAPI.base_url + "/api/login";
        var data = {
            email: email,
            password: password
        };
        return $.postJSON(url, data);
    },

    logout: function() {
        var url = pzAPI.base_url + "/api/logout";
        return $.postJSON(url);
    },

    signup: function(email, password, confirm_password) {
        var url = pzAPI.base_url + "/api/signup";
        var data = {
            email: email,
            password: password,
            confirm_password: confirm_password
        };
        return $.postJSON(url, data);
    },

    getCSRFToken: function() {
        var url = pzAPI.base_url + "/api/csrf_token";
        return $.getJSON(url);
    },

    getEntries: function() {
        var url = pzAPI.base_url + "/api/entries";
        return $.getJSON(url);
    },

    _createEntry: function(entry, csrf_token) {
        var url = pzAPI.base_url + "/api/entries/new";
        var data = pzAPI._copyObject(entry);
        data.csrf_token = csrf_token;
        return $.postJSON(url, data);
    },

    createEntry: function(entry) {
        return pzAPI.getCSRFToken()
        .then(function(response) {
            return pzAPI._createEntry(entry, response);
        });
    },

    _editEntry: function(entry_id, entry, csrf_token) {
        var url = "/api/entries/" + entry_id;
        var data = pzAPI._copyObject(entry);
        data.csrf_token = csrf_token;
        return $.postJSON(url, data);
    },

    editEntry: function(entry_id, entry) {
        return pzAPI.getCSRFToken()
        .then(function(response) {
            return pzAPI._editEntry(entry_id, entry, response);
        });
    }
};

if (module && module.exports) {
    module.exports = pzAPI;
}
