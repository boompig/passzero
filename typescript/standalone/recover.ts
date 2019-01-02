/// <reference types="jquery" />
/// <reference path="../common/passzero_api.ts" />

// module imports (tsc does not like these)
//import * as $ from "jquery";
//import { pzAPI } from "./common/passzero_api";


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

$(() => {
	$("#accept-risk").click(() => {
		const c = $("#accept-risk").prop("checked");
		console.log("checked = %s", c);
		$("button[type='submit']").prop("disabled", !c);
	});

	let elem = document.querySelector("#recover-form");
	console.log(elem);
	if (elem) {
			elem.addEventListener("submit", recoverPassword);
		} else {
			elem = document.querySelector("#recover-confirm-form");
			elem.addEventListener("submit", recoverPasswordConfirm);
		}
});

//export { recoverPassword, recoverPasswordConfirm };
