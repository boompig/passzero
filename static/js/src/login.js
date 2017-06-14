function getFormData(formElem) {
    var $elem = $(formElem);
    var dataArray = $elem.serializeArray();
    return parseArray(dataArray);
}

function createAccount(e) {
    "use strict";
    e.preventDefault();
    var data = getFormData(e.target);
    pzAPI.signup(data.email, data.password, data.confirm_password)
    .then(function(response) {
        console.log(response);
        window.location.href = "/done_signup/" + data.email;
        $("#error-msg-container").hide();
    }).catch(function(obj, textStatus, textCode) {
        if (textCode === "CONFLICT") {
            $("#error-msg").text("An account with this email already exists");
        } else if (textCode === "INTERNAL SERVER ERROR") {
            // clear out form-specific errors
            $(".form-error").text("");
            if(obj.responseJSON) {
                $("#error-msg").text(obj.responseJSON.msg);
            } else {
                $("#error-msg").text("Server error");
            }
        } else if (textCode === "BAD REQUEST") {
            var response = JSON.parse(obj.responseText);
            console.log(response);
            $("#error-msg").text(response.msg);

            $(".form-error").text("");

            for (var k in response) {
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

function login(e) {
    "use strict";
    e.preventDefault();
    var data = getFormData(e.target);
    pzAPI.login(data.email, data.password)
    .then(function(response) {
        //console.log(data);
        console.log(response);
        $("#error-msg-container").hide();
        if(data.remember) {
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
    }).catch(function(obj, textStatus, textCode) {
        console.log(obj);
        if (textCode === "UNAUTHORIZED" || textCode === "BAD REQUEST") {
            var response = JSON.parse(obj.responseText);
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

$(function() {
    var email = Cookies.get("email");
    if(email) {
        $("[name='remember']").prop("checked", true);
        $("[name='email']").val(email);
    }
});
