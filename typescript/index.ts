// imported externally
declare let $: any;
declare let LogoutTimer: any;


$(function() {
    "use strict";
    let timer = new LogoutTimer();
    timer.startLogoutTimer();
});
