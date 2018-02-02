// provided externally via CDN
declare let $: any;
declare let pzAPI: any;

// for type-checking
//import * as $ from "jquery";
//import { pzAPI } from "passzero_api";


function recoverPassword(e: Event) {
    e.preventDefault();
    const email = $("input[type='email']").val() as string;
	pzAPI.recoverAccount(email)
	.then((response) => {
		$("#success-msg").addClass("alert-success").text(response.msg).show();
		console.log(response);
	});
    return false;
}

function recoverPasswordConfirm(e: Event) {
    e.preventDefault();
    const password = $("input[name='password']").val() as string;
    const confirmPassword = $("input[name='confirm_password']").val() as string;
    const token = window.location.search.replace("?token=", "");
    pzAPI.recoverAccountConfirm(token, password, confirmPassword)
    .done((response, textStatus, obj) => {
        console.log(response);
        window.location.href = "/logout";
    })
    .catch((obj, textStatus, err) => {
        $("#server-msg").text(obj.responseJSON.msg);
        console.log("error");
        console.log(obj.responseJSON);
    });
    return false;
}

$(function () {
    $("#accept-risk").click(() => {
        const c = $("#accept-risk").prop("checked");
        console.log("checked = %s", c);
        $("button[type='submit']").prop("disabled", !c);
    });
});
