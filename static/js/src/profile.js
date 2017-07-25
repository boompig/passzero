//import Utils from "./utils"
//import pzAPI from "./passzero_api"
//export default class Profile {
var Profile = (function () {
    function Profile() {
    }
    Profile.renderState = function () {
        var key;
        console.log(Profile.state);
        // updatePassword state
        if (Profile.state.updatePassword.formErrorSet) {
            $("#change-password").find(".form-error").text("");
            console.log("Setting updatePassword error messages...");
            for (key in Profile.state.updatePassword.formErrors) {
                $("#form-error-" + key).text(Profile.state.updatePassword.formErrors[key]);
            }
        }
        else {
            // reset all form error messages
            $("#change-password").find(".form-error").text("");
        }
        // this is necessary because the operation is quite long
        if (Profile.state.updatePassword.inProgress) {
            $("#change-password").find(".progress-alert").text("Working...").show();
            $("#change-password").find("button[type='submit']")
                .prop("disabled", true);
        }
        else {
            $("#change-password").find(".progress-alert").hide();
            $("#change-password").find("button[type='submit']")
                .prop("disabled", false);
        }
        // updatePrefs state
        if (Profile.state.updatePrefs.formErrorSet) {
            $("#user-prefs").find(".form-error").text("");
            console.log("Setting updatePrefs error messages...");
            for (key in Profile.state.updatePrefs.formErrors) {
                $("#form-error-" + key).text(Profile.state.updatePrefs.formErrors[key]);
            }
        }
        else {
            // reset all form error messages
            $("#user-prefs").find(".form-error").text("");
        }
        // global state
        if (Profile.state.errorMsg) {
            $("#global-error-msg").show().find(".text").text(Profile.state.errorMsg);
        }
        else {
            $("#global-error-msg").hide();
        }
        if (Profile.state.successMsg) {
            $(".alert-success").text(Profile.state.successMsg).show();
        }
        else {
            $(".alert-success").hide();
        }
    };
    Profile.deleteUser = function (e) {
        "use strict";
        e.preventDefault();
        var password = Utils.getFormData(e.target).password;
        // set state on submit and re-render
        Profile.state.successMsg = null;
        Profile.state.errorMsg = null;
        // and render state
        Profile.renderState();
        pzAPI.deleteUser(password)
            .then(function (response) {
            window.location.href = "/post_account_delete";
        })["catch"](function (obj, textStatus, textCode) {
            Profile.state.successMsg = null;
            if (obj.responseJSON) {
                if (obj.status === 400 && textCode === "BAD REQUEST") {
                    Profile.state.errorMsg = "Incorrect password";
                }
                else {
                    var response = obj.responseJSON;
                    // set the state
                    Profile.state.errorMsg = response.msg;
                }
            }
            else if (textCode === "INTERNAL SERVER ERROR") {
                Profile.state.errorMsg = "Sorry about this! Looks like there was an internal server error. The site maintainer has been alerted";
            }
            // render the state
            Profile.renderState();
            console.log(obj);
            console.log(textStatus);
            console.log(textCode);
        });
        return false;
    };
    Profile.updatePrefs = function (e) {
        "use strict";
        if (!e) {
            throw "Event cannot be falsy";
        }
        e.preventDefault();
        var prefs = Utils.getFormData(e.target);
        if (Object.keys(prefs).length === 0) {
            throw "Form data cannot be empty";
        }
        // set state on submit and re-render
        Profile.state.successMsg = null;
        Profile.state.errorMsg = null;
        Profile.state.updatePrefs.formErrorSet = false;
        Profile.state.updatePrefs.formErrors = {};
        // and render state
        Profile.renderState();
        pzAPI.updateUserPreferences(prefs)
            .then(function (response) {
            // set the state
            Profile.state.successMsg = response.msg;
            Profile.state.errorMsg = null;
            Profile.state.updatePrefs.formErrorSet = false;
            Profile.state.updatePrefs.formErrors = {};
            // render state
            Profile.renderState();
        })["catch"](function (obj, textStatus, textCode) {
            Profile.state.successMsg = null;
            if (obj.responseJSON) {
                var response = obj.responseJSON;
                // set the state
                Profile.state.errorMsg = response.msg;
                Profile.state.updatePrefs.formErrorSet = true;
                Profile.state.updatePrefs.formErrors = {};
                for (var key in response) {
                    if (key !== "status" && key !== "msg") {
                        Profile.state.updatePrefs.formErrors[key] = response[key];
                    }
                }
            }
            else if (textCode === "INTERNAL SERVER ERROR") {
                Profile.state.errorMsg = "Sorry about this! Looks like there was an internal server error. The site maintainer has been alerted";
            }
            // render the state
            Profile.renderState();
            console.log(obj);
            console.log(textStatus);
            console.log(textCode);
        });
        return false;
    };
    Profile.updatePassword = function (e) {
        "use strict";
        e.preventDefault();
        var data = Utils.getFormData(e.target);
        if (Profile.state.updatePassword.inProgress) {
            console.log("Already in progress!");
            return;
        }
        // set state on submit and re-render
        Profile.state.updatePassword.inProgress = true;
        Profile.state.successMsg = null;
        Profile.state.errorMsg = null;
        Profile.state.updatePassword.formErrorSet = false;
        Profile.state.updatePassword.formErrors = {};
        // and render state
        Profile.renderState();
        pzAPI.updateUserPassword(data.old_password, data.new_password, data.confirm_new_password)
            .then(function (response) {
            var $elem = $(e.target);
            // reset form fields
            // TODO move this into state
            $elem.find("input[type='password']").each(function () {
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
        })["catch"](function (obj, textStatus, textCode) {
            var response = obj.responseJSON;
            // set the state
            Profile.state.updatePassword.inProgress = false;
            Profile.state.successMsg = null;
            Profile.state.errorMsg = response.msg;
            Profile.state.updatePassword.formErrorSet = true;
            Profile.state.updatePassword.formErrors = {};
            for (var key in response) {
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
    };
    return Profile;
}());
Profile.state = {
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
        formErrorSet: false
    }
};
