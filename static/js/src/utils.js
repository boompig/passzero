//import * as $ from "jquery";
//export default class Utils {
var Utils = (function () {
    function Utils() {
    }
    /**
    * Parse serliazed array into object
    */
    Utils.parseArray = function (arr) {
        "use strict";
        var obj = {};
        for (var i = 0; i < arr.length; i++) {
            obj[arr[i].name] = arr[i].value || "";
        }
        return obj;
    };
    /**
    * Given a DOM node representing a form, return object representing form data
    * Mapping of form element names to values
    */
    Utils.getFormData = function (formElem) {
        var $elem = $(formElem);
        var dataArray = $elem.serializeArray();
        return this.parseArray(dataArray);
    };
    return Utils;
}());
