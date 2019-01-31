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
    email: string;
    password: string;
    remember: boolean;
}


const Login = {

    createAccount: (e: Event) => {
        e.preventDefault();
        console.log(e.target);
        const data = Utils.getFormData(e.target as HTMLElement) as IRegisterFormData;
        pzAPI.signup(data.email, data.password, data.confirm_password)
        .done((response) => {
            console.log(response);
            window.location.href = "/done_signup/" + data.email;
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
                $("#error-msg").text(response.msg);

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

    login: (e: Event) => {
        "use strict";
        e.preventDefault();
        console.log(e.target);
        const data = Utils.getFormData(e.target as HTMLElement) as ILoginFormData;
        pzAPI.login(data.email, data.password)
        .done((response) => {
            //console.log(data);
            console.log(response);
            $("#error-msg-container").hide();
            if (data.remember) {
                // create a cookie on successful login
                Cookies.set("email", data.email, {
                    secure: true,
                    expires: 7
                });
            } else {
                // erase the cookie
                Cookies.remove("email");
            }
            window.location.href = "/done_login";
        }).catch((obj, textStatus, textCode) => {
            let errorMsg;
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
        const email: string = Cookies.get("email");
        if (email) {
            $("[name='remember']").prop("checked", true);
            $("[name='email']").val(email);
        }

        let form = document.querySelector("#login-existing-form");
        if (form) {
            form.addEventListener("submit", Login.login);
        } else {
            form = document.querySelector("#login-new-form");
            form.addEventListener("submit", Login.createAccount);
        }
    }
};

$(() => {
    Login.onLoad();
});

//export { Login };
