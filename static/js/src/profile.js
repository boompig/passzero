var state = {
    // these are global
    successMsg: null,
    errorMsg: null,
    changePassword: {
        formErrors: {},
        formErrorSet: false,
        inProgress: false
    },
    changePrefs: {
        formErrors: {},
        formErrorSet: false,
    }
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
    // changePassword state
    if(state.changePassword.formErrorSet) {
        $("#change-password").find(".form-error").text("");
        console.log("Setting error messages...");
        for(key in state.changePassword.formErrors) {
            $("#form-error-" + key).text(state.changePassword.formErrors[key]);
        }
    } else {
        // reset all form error messages
        $("#change-password").find(".form-error").text("");
    }
    // this is necessary because the operation is quite long
    if(state.changePassword.inProgress) {
        $("#change-password").find(".progress-alert").text("Working...").show();
        $("#change-password").find("button[type='submit']")
            .prop("disabled", true);
    } else {
        $("#change-password").find(".progress-alert").hide();
        $("#change-password").find("button[type='submit']")
            .prop("disabled", false);
    }

    // changePrefs state
    if(state.changePrefs.formErrorSet) {
        $("#prefs").find(".form-error").text("");
        console.log("Setting error messages...");
        for(key in state.changePrefs.formErrors) {
            $("#form-error-" + key).text(state.changePrefs.formErrors[key]);
        }
    } else {
        // reset all form error messages
        $("#prefs").find(".form-error").text("");
    }

    // global state
    if(state.errorMsg) {
        $(".alert-danger").text(state.errorMsg).show();
    } else {
        $(".alert-danger").hide();
    }
    if(state.successMsg) {
        $(".alert-success").text(state.successMsg).show();
    } else {
        $(".alert-success").hide();
    }
}

function savePrefs(e) {
    "use strict";
    e.preventDefault();
    var prefs = readFormData(e);
    
    // set state on submit and re-render
    state.successMsg = null;
    state.errorMsg = null;
    state.changePrefs.formErrorSet = false;
    state.changePrefs.formErrors = {};
    // and render state
    renderState(state);

    pzAPI.updateUserPreferences(prefs)
    .then(function (response) {
        var $elem = $(e.target);
        // set the state
        state.successMsg = response.msg;
        state.errorMsg = null;
        state.changePrefs.formErrorSet = false;
        state.changePrefs.formErrors = {};
        // render state
        renderState(state);
    })
    .catch(function (obj, textStatus, textCode) {
        state.successMsg = null;
        if(obj.responseJSON) {
            var response = obj.responseJSON;
            // set the state
            state.errorMsg = response.msg;
            state.changePrefs.formErrorSet = true;
            state.changePrefs.formErrors = {};
            for (var key in response) {
                if (key !== "status" && key !== "msg") {
                    state.changePrefs.formErrors[key] = response[key];
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

function changePassword(e) {
    "use strict";
    e.preventDefault();
    var data = readFormData(e);
    
    if(state.changePassword.inProgress) {
        console.log("Already in progress!");
        return;
    }

    // set state on submit and re-render
    state.changePassword.inProgress = true;
    state.successMsg = null;
    state.errorMsg = null;
    state.changePassword.formErrorSet = false;
    state.changePassword.formErrors = {};
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
        state.changePassword.inProgress = false;
        state.successMsg = "Successfully changed password";
        state.errorMsg = null;
        state.changePassword.formErrorSet = false;
        state.changePassword.formErrors = {};
        // render state
        renderState(state);
    })
    .catch(function (obj, textStatus, textCode) {
        var response = obj.responseJSON;
        // set the state
        state.changePassword.inProgress = false;
        state.successMsg = null;
        state.errorMsg = response.msg;
        state.changePassword.formErrorSet = true;
        state.changePassword.formErrors = {};
        for (var key in response) {
            if (key !== "status" && key !== "msg") {
                state.changePassword.formErrors[key] = response[key];
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

