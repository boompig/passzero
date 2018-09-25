/// <reference types="jquery" />
/// <reference path="./passzero_api.ts" />
/// <reference path="./utils.ts" />

// module imports (tsc doesn't like these)
//import * as $ from "jquery";
//import { Utils } from "./utils";
//import { pzAPI } from "./passzero_api";

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

$(() => {
	const elem = document.querySelector("#nuke-entries-form");
	if (elem) {
		elem.addEventListener("submit", nukeEntries);
	}
});

//export { nukeEntries };
