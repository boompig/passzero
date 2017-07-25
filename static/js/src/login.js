//import Utils from "./utils";
//import pzAPI from "./passzero_api";
//import * as Cookies from "js-cookie";
//import * as $ from "jquery";
function createAccount(e) {
    "use strict";
    e.preventDefault();
    var data = Utils.getFormData(e.target);
    pzAPI.signup(data.email, data.password, data.confirm_password)
        .then(function (response) {
        console.log(response);
        window.location.href = "/done_signup/" + data.email;
        $("#error-msg-container").hide();
    })["catch"](function (obj, textStatus, textCode) {
        if (textCode === "CONFLICT") {
            $("#error-msg").text("An account with this email already exists");
        }
        else if (textCode === "INTERNAL SERVER ERROR") {
            // clear out form-specific errors
            $(".form-error").text("");
            if (obj.responseJSON) {
                $("#error-msg").text(obj.responseJSON.msg);
            }
            else {
                $("#error-msg").text("Server error");
            }
        }
        else if (textCode === "BAD REQUEST") {
            var response = JSON.parse(obj.responseText);
            console.log(response);
            $("#error-msg").text(response.msg);
            $(".form-error").text("");
            for (var k in response) {
                if (k !== "status" && k !== "msg") {
                    $("#form-error-" + k).text(response[k]);
                }
            }
        }
        else {
            console.log(obj);
            console.log(textStatus);
            console.log(textCode);
        }
        $("#error-msg-container").show();
    });
    return false;
}
var loginPageState = {
    "errorMsg": null
};
/**
 * This is for the login page only
 */
function renderState() {
    if (loginPageState.errorMsg) {
        $("#error-msg").show().text(loginPageState.errorMsg);
        $("#error-msg-container").show();
    }
    else {
        $("#error-msg-container").hide();
    }
}
function login(e) {
    "use strict";
    e.preventDefault();
    var data = Utils.getFormData(e.target);
    pzAPI.login(data.email, data.password)
        .then(function (response) {
        //console.log(data);
        console.log(response);
        loginPageState.errorMsg = null;
        renderState();
        if (data.remember) {
            console.log("set cookie with email " + data.email);
            // create a cookie on successful login
            Cookies.set("email", data.email, {
                secure: true,
                expires: 7
            });
        }
        else {
            // erase the cookie
            Cookies.remove("email");
        }
        window.location.href = "/done_login";
    })["catch"](function (obj, textStatus, textCode) {
        console.log(obj);
        if (textCode === "UNAUTHORIZED" || textCode === "BAD REQUEST") {
            var response = JSON.parse(obj.responseText);
            loginPageState.errorMsg = response.msg;
        }
        else if (textCode === "INTERNAL SERVER ERROR") {
            loginPageState.errorMsg = "Sorry about this! Internal server error. Site maintainer has been alerted.";
        }
        else {
            console.log(obj);
            console.log(textStatus);
            console.log(textCode);
        }
        renderState();
    });
    return false;
}
$(function () {
    var email = Cookies.get("email");
    console.log(email);
    if (email) {
        $("[name='remember']").prop("checked", true);
        $("[name='email']").val(email);
    }
});
