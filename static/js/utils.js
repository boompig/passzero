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
