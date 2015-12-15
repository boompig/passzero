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

    login: function(email, password) {
        var url = pzAPI.base_url + "/api/login";
        var data = {
            email: email,
            password: password
        };
        return $.postJSON(url, data);
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
};

if (module && module.exports) {
    module.exports = pzAPI;
}
