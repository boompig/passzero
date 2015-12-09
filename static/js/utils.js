/**
 * Parse serliazed array into object
 */
function parseArray(arr) {
    "use strict";
    var obj = {};
    for(var i = 0; i < arr.length; i++) {
        obj[arr[i].name] = arr[i].value || "";
    }
    return obj;
}

function postJSON (url, data) {
    return $.ajax({
        url: url,
        data: JSON.stringify(data),
        method: "POST",
        dataType: "json",
        contentType: "application/json"
    });
}
