/*
 * These files are provided externally via script tags
 */
/// <reference types="jquery" />
/// <reference types="js-cookie" />
/// <reference path="./passzero_api.ts" />
/// <reference path="./logoutTimer.ts" />
/// <reference path="./utils.ts" />


// module imports (tsc does not like these)
//import * as $ from "jquery";
//import { pzAPI } from "passzero_api";
//import { Utils } from "utils";


interface IRegisterFormData {
    email: string;
    password: string;
    confirm_password: string;
}

interface ILoginFormData {
    email: string;
    password: string;
    remember: boolean;
}


const Login = {

	createAccount: function(e: Event) {
		e.preventDefault();
		console.log(e.target);
		const data = Utils.getFormData(e.target as HTMLElement) as IRegisterFormData;
		pzAPI.signup(data.email, data.password, data.confirm_password)
		.done((response) => {
			console.log(response);
			window.location.href = "/done_signup/" + data.email;
			$("#error-msg-container").hide();
		}).catch((obj, textStatus, textCode) => {
			if (textCode === "CONFLICT") {
				$("#error-msg").text("An account with this email already exists");
			} else if (textCode === "INTERNAL SERVER ERROR") {
				// clear out form-specific errors
				$(".form-error").text("");
				if (obj.responseJSON) {
					$("#error-msg").text(obj.responseJSON.msg);
				} else {
					$("#error-msg").text("Server error");
				}
			} else if (textCode === "BAD REQUEST") {
				const response = JSON.parse(obj.responseText);
				console.log(response);
				$("#error-msg").text(response.msg);

				$(".form-error").text("");

				for (const k of response) {
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
	},

	login: function(e: Event) {
		"use strict";
		e.preventDefault();
		console.log(e.target);
		const data = Utils.getFormData(e.target as HTMLElement) as ILoginFormData;
		pzAPI.login(data.email, data.password)
		.done((response) => {
			//console.log(data);
			console.log(response);
			$("#error-msg-container").hide();
			if (data.remember) {
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
		}).catch((obj, textStatus, textCode) => {
			console.log(obj);
			if (textCode === "UNAUTHORIZED" || textCode === "BAD REQUEST") {
				const response = JSON.parse(obj.responseText);
				$("#error-msg").text(response.msg);
			} else {
				console.log(obj);
				console.log(textStatus);
				console.log(textCode);
			}
			$("#error-msg-container").show();
		});
		return false;
	},

	onLoad: function() {
		const email: string = Cookies.get("email");
		if (email) {
			$("[name='remember']").prop("checked", true);
			$("[name='email']").val(email);
		}
	}
}

$(() => {
	Login.onLoad();
});

//export { Login };
