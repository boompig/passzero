/*
 * These files are provided externally via script tags
 */
/// <reference types="jquery" />
/// <reference path="./utils.ts" />
/// <reference path="../common/passzero_api.ts" />


// module imports (tsc does not like these)
//import * as $ from "jquery";
//import { Utils } from "./utils";
// import { pzAPI } from "../common/passzero_api";

interface IPrefsForm {
    default_random_passphrase_length: number;
    default_random_password_length: number;
}

interface IDeleteUserForm {
    password: string;
    csrf_token: string;
}

interface IChangePasswordForm {
    old_password: string;
    new_password: string;
    confirm_new_password: string;
    csrf_token: string;
}

interface ICommandWithErrors {
    formErrors: any;
    formErrorSet: boolean;
    inProgress: boolean;
}

interface IState {
    successMsg: string | null;
    errorMsg: string | null;
    updatePassword: ICommandWithErrors;
    updatePrefs: ICommandWithErrors;
}

class Profile {
    static state: IState = {
        // these are global
        successMsg: null,
        errorMsg: null,
        updatePassword: {
            formErrors: {},
            formErrorSet: false,
            inProgress: false
        },
        updatePrefs: {
            formErrors: {},
            formErrorSet: false,
            inProgress: false
        }
    };

    static renderState() {
        console.log(Profile.state);
        // updatePassword state
        if (Profile.state.updatePassword.formErrorSet) {
            $("#change-password").find(".form-error").text("");
            console.log("Setting updatePassword error messages...");
            for (const key in Profile.state.updatePassword.formErrors) {
                $("#form-error-" + key).text(Profile.state.updatePassword.formErrors[key]);
            }
        } else {
            // reset all form error messages
            $("#change-password").find(".form-error").text("");
        }
        // this is necessary because the operation is quite long
        if (Profile.state.updatePassword.inProgress) {
            $("#change-password").find(".progress-alert").text("Working...").show();
            $("#change-password").find("button[type='submit']")
                .prop("disabled", true);
        } else {
            $("#change-password").find(".progress-alert").hide();
            $("#change-password").find("button[type='submit']")
                .prop("disabled", false);
        }
        // updatePrefs state
        if (Profile.state.updatePrefs.formErrorSet) {
            $("#user-prefs").find(".form-error").text("");
            console.log("Setting updatePrefs error messages...");
            for (const key in Profile.state.updatePrefs.formErrors) {
                $("#form-error-" + key).text(Profile.state.updatePrefs.formErrors[key]);
            }
        } else {
            // reset all form error messages
            $("#user-prefs").find(".form-error").text("");
        }
        // global state
        if (Profile.state.errorMsg) {
            $("#global-error-msg").show().find(".text").text(Profile.state.errorMsg);
        } else {
            $("#global-error-msg").hide();
        }
        if (Profile.state.successMsg) {
            $(".alert-success").text(Profile.state.successMsg).show();
        } else {
            $(".alert-success").hide();
        }
    }

    static deleteUser(e: Event) {
        e.preventDefault();
        const password = (Utils.getFormData(e.target as HTMLElement) as IDeleteUserForm)
                        .password;
        // set state on submit and re-render
        Profile.state.successMsg = null;
        Profile.state.errorMsg = null;
        // and render state
        Profile.renderState();
        pzAPI.deleteUser(password)
        .done((response, textStatus, obj) => {
            window.location.assign("/post_account_delete");
        })
        .catch((obj, textStatus, textCode) => {
            Profile.state.successMsg = null;
            if (obj.responseJSON) {
                if (obj.status === 400 && textCode === "BAD REQUEST") {
                    Profile.state.errorMsg = "Incorrect password";
                } else {
                    const response = obj.responseJSON;
                    // set the state
                    Profile.state.errorMsg = response.msg;
                }
            } else if (textCode === "INTERNAL SERVER ERROR") {
                Profile.state.errorMsg = "Sorry about this! Looks like there was an internal server error. The site maintainer has been alerted";
            }
            // render the state
            Profile.renderState();
            console.log(obj);
            console.log(textStatus);
            console.log(textCode);
        });
        return false;
    }

    static updatePrefs(e: Event): boolean {
        if (!e) {
            throw Error("Event cannot be falsy");
        }
        e.preventDefault();
        const prefs = Utils.getFormData(e.target as HTMLElement) as IPrefsForm;
        if (Object.keys(prefs).length === 0) {
            throw Error("Form data cannot be empty");
        }
        // set state on submit and re-render
        Profile.state.successMsg = null;
        Profile.state.errorMsg = null;
        Profile.state.updatePrefs.formErrorSet = false;
        Profile.state.updatePrefs.formErrors = {};
        // and render state
        Profile.renderState();
        pzAPI.updateUserPreferences(prefs)
        .done((response, textStatus, obj) => {
            // set the state
            Profile.state.successMsg = response.msg;
            Profile.state.errorMsg = null;
            Profile.state.updatePrefs.formErrorSet = false;
            Profile.state.updatePrefs.formErrors = {};
            // render state
            Profile.renderState();
        })
        .catch((obj, textStatus, textCode) => {
            Profile.state.successMsg = null;
            if (obj.responseJSON) {
                const response = obj.responseJSON;
                // set the state
                Profile.state.errorMsg = response.msg;
                Profile.state.updatePrefs.formErrorSet = true;
                Profile.state.updatePrefs.formErrors = {};
                for (const key in response) {
                    if (key !== "status" && key !== "msg") {
                        Profile.state.updatePrefs.formErrors[key] = response[key];
                    }
                }
            } else if (textCode === "INTERNAL SERVER ERROR") {
                Profile.state.errorMsg = "Sorry about this! Looks like there was an internal server error. The site maintainer has been alerted";
            }
            // render the state
            Profile.renderState();
            console.log(obj);
            console.log(textStatus);
            console.log(textCode);
        });
        return false;
    }

    static updatePassword(e: Event): boolean {
        "use strict";
        e.preventDefault();
        const data = Utils.getFormData(e.target as HTMLElement) as IChangePasswordForm;
        if (Profile.state.updatePassword.inProgress) {
            console.log("Already in progress!");
            return false;
        }
        // set state on submit and re-render
        Profile.state.updatePassword.inProgress = true;
        Profile.state.successMsg = null;
        Profile.state.errorMsg = null;
        Profile.state.updatePassword.formErrorSet = false;
        Profile.state.updatePassword.formErrors = {};
        // and render state
        Profile.renderState();
        pzAPI.changeAccountPassword(data.old_password, data.new_password, data.confirm_new_password)
        .done((response, textStatus, obj) => {
            const $elem = $(e.target);
            // reset form fields
            // TODO move this into state
            $elem.find("input[type='password']").each(() => {
                $(this).val("");
            });
            // set the state
            Profile.state.updatePassword.inProgress = false;
            Profile.state.successMsg = "Successfully changed password";
            Profile.state.errorMsg = null;
            Profile.state.updatePassword.formErrorSet = false;
            Profile.state.updatePassword.formErrors = {};
            // render state
            Profile.renderState();
        })
        .catch((obj, textStatus, textCode) => {
            const response = obj.responseJSON;
            // set the state
            Profile.state.updatePassword.inProgress = false;
            Profile.state.successMsg = null;
            Profile.state.errorMsg = response.msg;
            Profile.state.updatePassword.formErrorSet = true;
            Profile.state.updatePassword.formErrors = {};
            for (const key in response) {
                if (key !== "status" && key !== "msg") {
                    Profile.state.updatePassword.formErrors[key] = response[key];
                }
            }
            // render the state
            Profile.renderState();
            console.log(obj);
            console.log(textStatus);
            console.log(textCode);
        });
        return false;
    }

    static onLoad() {
        let elem = document.querySelector("#user-prefs-form");
        if (elem) {
            elem.addEventListener("submit", Profile.updatePrefs);
        }
        elem = document.querySelector("#delete-user-form");
        if (elem) {
            elem.addEventListener("submit", Profile.deleteUser);
        }
        elem = document.querySelector("#change-password-form");
        if (elem) {
            elem.addEventListener("submit", Profile.updatePassword);
        }
    }
}

$(() => {
    Profile.onLoad();
});

//export { Profile };
