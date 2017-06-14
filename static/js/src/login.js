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
    .done(function(response) {
        console.log(response);
        window.location.href = "/done_signup/" + data.email;
        $("#error-msg-container").hide();
        $(".form-error").hide();
    }).error(function(obj, textStatus, textCode) {
        if (textCode === "CONFLICT") {
            $("#error-msg").text("An account with this email already exists");
        } else if (textCode === "INTERNAL SERVER ERROR") {
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
                    console.log(response[k]);
                    console.log(k);
                    console.log($("#form-error-" + k));
                    $("#form-error-" + k).text(response[k]).show();
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

var LoginForm = function() {
    this.email = "";
    this.remember = false;

    this.updateEmail = function(e) {
        this.email = e.target.value;
        console.log("email = " + this.email);
        if(this.remember) {
            this.saveEmail();
        }
    };

    this.saveEmail = function() {
        if(this.email && this.remember) {
            console.log("saving email " + this.email);
            // create a cookie when the checkbox is checked
            Cookies.set("email", this.email, {
                secure: true,
                expires: 7
            });
        }
    };

    this.checkRemember = function (e) {
        this.remember = e.target.checked;
        console.log("remember = " + this.remember);
        if(this.remember) {
            this.saveEmail();
        } else {
            // erase the cookie
            Cookies.remove("email");
        }
    };

    this.init = function() {
        var email = Cookies.get("email");
        console.log(email);
        if(email) {
            $("[name='remember']").prop("checked", true);
            $("[name='email']").val(email);
            this.email = email;
            this.remember = true;
        }
    };

    return this;
}();

$(function() {
    LoginForm.init();
});
