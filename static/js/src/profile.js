var state = {
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
    },
};

function readFormData(e) {
    var elem = $(e.target);
    var url = elem.attr("action");
    var dataArray = elem.serializeArray();
    var data = parseArray(dataArray);
    return data;
}

function renderState(state) {
    var key;
    console.log(state);
    // updatePassword state
    if(state.updatePassword.formErrorSet) {
        $("#change-password").find(".form-error").text("");
        console.log("Setting updatePassword error messages...");
        for(key in state.updatePassword.formErrors) {
            $("#form-error-" + key).text(state.updatePassword.formErrors[key]);
        }
    } else {
        // reset all form error messages
        $("#change-password").find(".form-error").text("");
    }

    // this is necessary because the operation is quite long
    if(state.updatePassword.inProgress) {
        $("#change-password").find(".progress-alert").text("Working...").show();
        $("#change-password").find("button[type='submit']")
            .prop("disabled", true);
    } else {
        $("#change-password").find(".progress-alert").hide();
        $("#change-password").find("button[type='submit']")
            .prop("disabled", false);
    }

    // updatePrefs state
    if(state.updatePrefs.formErrorSet) {
        $("#user-prefs").find(".form-error").text("");
        console.log("Setting updatePrefs error messages...");
        for(key in state.updatePrefs.formErrors) {
            $("#form-error-" + key).text(state.updatePrefs.formErrors[key]);
        }
    } else {
        // reset all form error messages
        $("#user-prefs").find(".form-error").text("");
    }

    // global state
    if(state.errorMsg) {
        $("#global-error-msg").show().find(".text").text(state.errorMsg);
    } else {
        $("#global-error-msg").hide();
    }
    if(state.successMsg) {
        $(".alert-success").text(state.successMsg).show();
    } else {
        $(".alert-success").hide();
    }
}

function deleteUser(e) {
    "use strict";
    e.preventDefault();
    var password = readFormData(e).password;
    
    // set state on submit and re-render
    state.successMsg = null;
    state.errorMsg = null;
    // and render state
    renderState(state);

    pzAPI.deleteUser(password)
    .then(function (response) {
        window.location.href = "/post_account_delete";
    })
    .catch(function (obj, textStatus, textCode) {
        state.successMsg = null;
        if(obj.responseJSON) {
            if(obj.status === 400 && textCode === "BAD REQUEST") {
                state.errorMsg = "Incorrect password";
            } else {
                var response = obj.responseJSON;
                // set the state
                state.errorMsg = response.msg;
            }
        } else if(textCode === "INTERNAL SERVER ERROR") {
            state.errorMsg = "Sorry about this! Looks like there was an internal server error. The site maintainer has been alerted";
        }
        // render the state
        renderState(state);
        console.log(obj);
        console.log(textStatus);
        console.log(textCode);
    });

    return false;
}

function updatePrefs(e) {
    "use strict";
    e.preventDefault();
    var prefs = readFormData(e);
    
    // set state on submit and re-render
    state.successMsg = null;
    state.errorMsg = null;
    state.updatePrefs.formErrorSet = false;
    state.updatePrefs.formErrors = {};
    // and render state
    renderState(state);

    pzAPI.updateUserPreferences(prefs)
    .then(function (response) {
        var $elem = $(e.target);
        // set the state
        state.successMsg = response.msg;
        state.errorMsg = null;
        state.updatePrefs.formErrorSet = false;
        state.updatePrefs.formErrors = {};
        // render state
        renderState(state);
    })
    .catch(function (obj, textStatus, textCode) {
        state.successMsg = null;
        if(obj.responseJSON) {
            var response = obj.responseJSON;
            // set the state
            state.errorMsg = response.msg;
            state.updatePrefs.formErrorSet = true;
            state.updatePrefs.formErrors = {};
            for (var key in response) {
                if (key !== "status" && key !== "msg") {
                    state.updatePrefs.formErrors[key] = response[key];
                }
            }
        } else if(textCode === "INTERNAL SERVER ERROR") {
            state.errorMsg = "Sorry about this! Looks like there was an internal server error. The site maintainer has been alerted";
        }
        // render the state
        renderState(state);
        console.log(obj);
        console.log(textStatus);
        console.log(textCode);
    });

    return false;
}

function updatePassword(e) {
    "use strict";
    e.preventDefault();
    var data = readFormData(e);
    
    if(state.updatePassword.inProgress) {
        console.log("Already in progress!");
        return;
    }

    // set state on submit and re-render
    state.updatePassword.inProgress = true;
    state.successMsg = null;
    state.errorMsg = null;
    state.updatePassword.formErrorSet = false;
    state.updatePassword.formErrors = {};
    // and render state
    renderState(state);

    pzAPI.updateUserPassword(data.old_password, data.new_password, data.confirm_new_password)
    .then(function (response) {
        var $elem = $(e.target);
        // reset form fields
        // TODO move this into state
        $elem.find("input[type='password']").each(function (idx) {
            $(this).val("");
        });

        // set the state
        state.updatePassword.inProgress = false;
        state.successMsg = "Successfully changed password";
        state.errorMsg = null;
        state.updatePassword.formErrorSet = false;
        state.updatePassword.formErrors = {};
        // render state
        renderState(state);
    })
    .catch(function (obj, textStatus, textCode) {
        var response = obj.responseJSON;
        // set the state
        state.updatePassword.inProgress = false;
        state.successMsg = null;
        state.errorMsg = response.msg;
        state.updatePassword.formErrorSet = true;
        state.updatePassword.formErrors = {};
        for (var key in response) {
            if (key !== "status" && key !== "msg") {
                state.updatePassword.formErrors[key] = response[key];
            }
        }
        // render the state
        renderState(state);
        console.log(obj);
        console.log(textStatus);
        console.log(textCode);
    });

    return false;
}

