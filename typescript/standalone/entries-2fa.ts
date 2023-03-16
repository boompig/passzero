// import * as $ from "jquery";
// import "tablesorter";

/// <reference path="../common/logoutTimer.ts" />

// tablesorter interface
interface JQuery { // tslint:disable-line
    tablesorter(arg0: any): void; // tslint:disable-line
}

// assume jquery and tablesorter are loaded
$(() => {
    $("#2fa-audit-table").tablesorter({
        theme: "bootstrap",
    });
});
