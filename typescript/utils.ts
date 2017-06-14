// provided externally via CDN
declare let $: any;

interface NameValuePair {
    name: string;
    value: string;
}

const Utils = {

    /**
    * Parse serliazed array into object
    */
    parseArray: function(arr: Array<NameValuePair>) {
        "use strict";
        let obj = {};
        for(let i = 0; i < arr.length; i++) {
            obj[arr[i].name] = arr[i].value || "";
        }
        return obj;
    },

    /**
    * Given a DOM node representing a form, return object representing form data
    * Mapping of form element names to values
    */
    getFormData: function(formElem: HTMLElement) {
        let $elem = $(formElem);
        let dataArray = $elem.serializeArray();
        return Utils.parseArray(dataArray);
    }
};
