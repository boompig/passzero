// provided externally via CDN
declare let $: any;
declare let Cookies: any;

// instead of requiring we put them at top-level
//const Utils = require("./utils.js");
//const pzAPI = require("./passzero_api.js");
declare let Utils: any;
declare let pzAPI: any;

interface IRegisterFormData {
    email: string;
    password: string;
    confirm_password: string;
}

function createAccount(e: Event) {
    e.preventDefault();
    const data: IRegisterFormData = Utils.getFormData(e.target);
    pzAPI.signup(data.email, data.password, data.confirm_password)
    .then((response) => {
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
}

interface ILoginFormData {
    email: string;
    password: string;
    remember: boolean;
}

function login(e: Event) {
    "use strict";
    e.preventDefault();
    const data: ILoginFormData = Utils.getFormData(e.target);
    pzAPI.login(data.email, data.password)
    .then((response) => {
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
        console.log(obj);
        if (textCode === "UNAUTHORIZED" || textCode === "BAD REQUEST") {
            const response = JSON.parse(obj.responseText);
            $("#error-msg").text(response.msg);
        } else {
            console.log(obj);
            console.log(textStatus);
            console.log(textCode);
        }
        $("#error-msg-container").show();
    });
    return false;
}

$(() => {
    const email: string = Cookies.get("email");
    if (email) {
        $("[name='remember']").prop("checked", true);
        $("[name='email']").val(email);
    }
});
