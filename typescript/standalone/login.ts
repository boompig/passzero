/*
 * These files are provided externally via script tags
 */
/// <reference types="jquery" />
/// <reference types="js-cookie" />
/// <reference path="../common/passzero_api.ts" />
/// <reference path="./utils.ts" />


// module imports (tsc does not like these)
// import * as $ from "jquery";
// import { pzAPI } from "../common/passzero_api";
// import * as Cookies from "js-cookie";
// import { Utils } from "./utils";


interface IRegisterFormData {
    email: string;
    password: string;
    confirm_password: string;
}

interface ILoginFormData {
    username_or_email: string;
    password: string;
    remember: boolean;
}


const Login = {
    /**
     * A timer to show a message saying that we're logging in
     * Useful on slow connections
     */
    loginTimer: null,

    isRequestComplete: true,

    createAccount: (e: Event) => {
        e.preventDefault();
        console.debug(e.target);
        const data = Utils.getFormData(e.target as HTMLElement) as IRegisterFormData;
        pzAPI.signup(data.email, data.password, data.confirm_password)
        .done((response) => {
            console.debug(response);
            window.location.assign("/done_signup/" + data.email);

            // clear error message
            $("#error-msg-container").hide();
        }).catch((obj, textStatus, textCode) => {
            if (textCode === "CONFLICT") {
                $("#error-msg").text("An account with this email already exists");
            } else if (textCode === "INTERNAL SERVER ERROR") {
                // clear out form-specific errors
                $(".form-error").text("");
                if (obj.responseJSON) {
                    $("#error-msg").text(obj.responseJSON.msg);
                } else {
                    $("#error-msg").text("Server error");
                }
            } else if (textCode === "BAD REQUEST") {
                const response = JSON.parse(obj.responseText);
                console.log(response);
                // set global error message
                $("#error-msg").text(response.msg);

                // clear form-level error messages
                $(".form-error").text("");

                for (const k of response) {
                    if (k !== "status" && k !== "msg") {
                        $("#form-error-" + k).text(response[k]);
                    }
                }
            } else {
                console.log(obj);
                console.log(textStatus);
                console.log(textCode);
            }
            $("#error-msg-container").show();
        });
        return false;
    },

    updateProgressAlert: () => {
        if (Login.isRequestComplete && Login.loginTimer) {
            $("#progress-alert").hide();
            // request is done
            window.clearInterval(Login.loginTimer);
            Login.loginTimer = null;
        } else if (!Login.isRequestComplete && Login.loginTimer) {
            $("#progress-alert").show();
        }
    },

    login: (e: Event) => {
        "use strict";
        e.preventDefault();
        console.log(e.target);
        const data = Utils.getFormData(e.target as HTMLElement) as ILoginFormData;

        // clear previous error messages
        $("#error-msg").text("");
        $("#error-msg-container").hide();

        // start the timer to show a progress message
        Login.isRequestComplete = false;
        Login.loginTimer = window.setInterval(Login.updateProgressAlert, 380);

        pzAPI.login(data.username_or_email, data.password)
        .done((response) => {
            Login.isRequestComplete = true;
            $("#progress-alert").hide();

            //console.log(data);
            console.debug(response);
            $("#error-msg-container").hide();
            if (data.remember) {
                // create a cookie on successful login
                Cookies.set("username_or_email", data.username_or_email, {
                    secure: true,
                    expires: 7
                });
            } else {
                // erase the cookie
                Cookies.remove("username_or_email");
            }
            window.location.assign("/done_login");
        }).catch((obj, textStatus, textCode) => {
            Login.isRequestComplete = true;
            $("#progress-alert").hide();

            let errorMsg = null;
            console.log(obj);
            if (textCode === "UNAUTHORIZED" || textCode === "BAD REQUEST") {
                const response = JSON.parse(obj.responseText);
                errorMsg = response.msg;
            } else if (textCode === "INTERNAL SERVER ERROR") {
                errorMsg = "There was a server-side error processing your request. The site maintainer has been notified";
            } else {
                console.log(obj);
                console.log(textStatus);
                console.log(textCode);
                errorMsg = textCode;
            }
            $("#error-msg").text(errorMsg);
            $("#error-msg-container").show();
        });
        return false;
    },

    onLoad: () => {
        const usernameOrEmail: string = Cookies.get("username_or_email");
        if (usernameOrEmail) {
            $("[name='remember']").prop("checked", true);
            $("[name='username_or_email']").val(usernameOrEmail);
        }

        let form = document.querySelector("#login-existing-form");
        if (form) {
            form.addEventListener("submit", Login.login);
        } else {
            form = document.querySelector("#login-new-form");
            form.addEventListener("submit", Login.createAccount);
        }

        // make a network request to wake up the server if it was previously asleep
        pzAPI.getStatus().then(() => {
            console.debug("Got response back from status API");
        });
    }
};

$(() => {
    Login.onLoad();
});

//export { Login };
