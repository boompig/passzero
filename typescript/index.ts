/// <reference types="jquery" />
/// <reference path="./logoutTimer.ts" />


// type-checking
//import * as $ from "jquery";
//import { LogoutTimer } from "./logoutTimer";


$(() => {
	const timer = new LogoutTimer();
	timer.startLogoutTimer();
});
