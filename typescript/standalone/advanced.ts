/// <reference types="jquery" />
/// <reference path="../common/passzero_api.ts" />
/// <reference path="./utils.ts" />

// module imports (tsc doesn't like these)
// import * as $ from "jquery";
// import { Utils } from "./utils";
// import { pzAPI } from "../common/passzero_api";

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

function updateEntryVersions(e: Event) {
    "use strict";
    e.preventDefault();
    const api = new PasszeroApiv3();
    const masterPassword = $("#update-entry-versions form .master-password").val() as string;
    api.updateEntryVersions(masterPassword)
        .then((numUpdated) => {
            $("#update-entry-versions .success-msg").text(`Updated ${numUpdated} entries`).show();
        });
}

$(() => {
    let elem = document.querySelector("#nuke-entries-form");
    if (elem) {
        elem.addEventListener("submit", nukeEntries);
    }

    elem = document.querySelector("#update-entry-versions form");
    if (elem) {
        elem.addEventListener("submit", updateEntryVersions);
    }
});

//export { nukeEntries };
