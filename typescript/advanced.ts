/// <reference types="jquery" />
/// <reference path="./passzero_api.ts" />
/// <reference path="./utils.ts" />


// module imports (tsc doesn't like these)
//import * as $ from "jquery";
//import { Utils } from "./utils";
//import { pzAPI } from "./passzero_api";


interface IChangeAccountPasswordData {
	old_password: string;
	new_password: string;
	confirm_new_password: string;
}

function changePassword(e: Event) {
	"use strict";
	e.preventDefault();

	const elem = $(e.target);
	const dataArray = elem.serializeArray();
	const data = Utils.parseArray(dataArray) as IChangeAccountPasswordData;

	$(".form-error").text("");
	$(".error-msg").text("");
	$(".alert-success").hide();

	pzAPI.changeAccountPassword(data.old_password, data.new_password, data.confirm_new_password)
	.done((response) => {
		$(".alert-success").text("Successfully changed password").show();
		// reset form fields
		elem.find("input[type='password']").each((idx) => {
			$(this).val("");
		});
	})
	.catch((obj, textStatus, textCode) => {
		const response = obj.responseJSON;
		$(".error-msg").text(response.msg);

		for (const key in response) {
			if (key !== "status" && key !== "msg") {
				$("#form-error-" + key).text(response[key]);
			}
		}
		console.log(obj);
		console.log(textStatus);
		console.log(textCode);
	});

	return false;
}

function nukeEntries(e: Event) {
	"use strict";
	e.preventDefault();
	if (confirm("Are you sure you want to delete all your entries?")) {
		pzAPI.deleteAllEntries()
		.then((response) => {
			$("#nuke-success-msg").text(response.msg).show();
		});
	}
	return false;
}

//export { changePassword, nukeEntries };
