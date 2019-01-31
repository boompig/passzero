// provided externally via script tags
/// <reference types="jquery" />


// used during type checking
//import * as $ from "jquery";

interface INameValuePair {
    name: string;
    value: string;
}

const Utils = {

    /**
     * Parse serliazed array into object
     */
    parseArray: (arr: INameValuePair[]): any => {
        const obj: any = {};
        for (let i = 0; i < arr.length; i++) {
            obj[arr[i].name] = arr[i].value || "";
        }
        return obj;
    },

    /**
     * Given a DOM node representing a form, return object representing form data
     * Mapping of form element names to values
     */
    getFormData: (formElem: HTMLElement) => {
        const $elem = $(formElem);
        const dataArray = $elem.serializeArray();
        return Utils.parseArray(dataArray);
    }
};

//export { Utils };
