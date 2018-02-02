// provided via CDN
declare let $: any;

// imported externally
declare let LogoutTimer: any;

// type-checking
//import * as $ from "jquery";
//import { LogoutTimer } from "./logoutTimer";


$(function() {
    let timer = new LogoutTimer();
    timer.startLogoutTimer();
});
