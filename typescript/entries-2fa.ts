// import * as $ from "jquery";
// import "tablesorter";

// tablesorter interface
interface JQuery { // tslint:disable-line
	tablesorter(any): void; // tslint:disable-line
}

// assume jquery and tablesorter are loaded
$(() => {
	$("#2fa-audit-table").tablesorter({
		theme: "bootstrap",
	});
});
