// provided externally via CDN
declare let $: any;

//const pzAPI = require("./passzero_api.js");
declare let pzAPI: any;

function recoverPassword(e: Event) {
    "use strict";
    e.preventDefault();
    const email = $("input[type='email']").val();
    pzAPI.recoverAccount(email)
    .then(function(response, textStatus, obj) {
        $("#success-msg").addClass("alert-success").text(response.msg).show();
        console.log(response);
    });
    return false;
}

function recoverPasswordConfirm(e: Event) {
    "use strict";
    e.preventDefault();
    const password = $("input[name='password']").val();
    const confirmPassword = $("input[name='confirm_password']").val();
    const token = window.location.search.replace("?token=", "");
    pzAPI.recoverAccountConfirm(token, password, confirmPassword)
    .then(function(response, textStatus, obj) {
        console.log(response);
        window.location.href = "/logout";
    })
    .catch(function(obj, b) {
        $("#server-msg").text(obj.responseJSON.msg);
        console.log("error");
        console.log(obj.responseJSON);
    });
    return false;
}

$(function () {
    "use strict";

    $("#accept-risk").click(function() {
        const c = $("#accept-risk").prop("checked");
        console.log("checked = %s", c);
        $("button[type='submit']").prop("disabled", !c);
    });
});
