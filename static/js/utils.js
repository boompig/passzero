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

/**
 * Given a DOM node representing a form, return object representing form data
 * Mapping of form element names to values
 */
function getFormData(formElem) {
    var $elem = $(formElem);
    var dataArray = $elem.serializeArray();
    return parseArray(dataArray);
}
