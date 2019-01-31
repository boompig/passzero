/// <reference types="jquery" />
/// <reference types="angular" />
/// <reference types="clipboard" />
/// <reference path="../common/logoutTimer.ts" />
/// <reference path="../common/passzero_api.ts" />
/// <reference path="./utils.ts" />
/// <reference path="../common/interfaces.ts" />


// type-checking
// import * as $ from "jquery";
// import { Utils } from "./utils";
// import { pzAPI } from "../common/passzero_api";
// import * as Clipboard from "clipboard";
// import { LogoutTimer } from "./LogoutTimer";


/**
 * Get a random integer in interval [a, b)
 */
function randInt(a: number, b: number) {
    return Math.floor(Math.random() * (b - a) + a);
}

const NewCtrl = function() {
    /**
     * form data
     */
    this.entry = {
        id: -1,
        account: "",
        username: "",
        password: "",
        extra: "",
        version: -1,
    };

    /**
     * UI settings
     */
    this.showSettings = false;
    this.passwordIsVisible = false;

    /**
     * Settings for password generation
     */
    this.useSpecialChars = true;
    /* number of words for word-generated passwords */
    this.numWords = 5;
    this.passwordGenMode = "password";
    /* the length for character-generated passwords */
    this.passwordLength = 16;
    this.words = [];
    /* name of the list of words to use, as stored on the server */
    this.dictionary = "common.txt";
    this.charSet = [];

    /* logout timer */
    this.timer = null;

    this.showHideSettings = () => {
        this.showSettings = !this.showSettings;
    };

    /**
     * Return the passphrase that has been generated from the given corpus of words
     */
    this.genPassphraseHelper = (words: string[], numWords: number): string => {
        let phrase = "";
        for (let i = 0; i < numWords; i++) {
            let word = words[randInt(0, words.length)];
            word = word[0].toUpperCase() + word.substr(1);
            phrase += word;
        }
        return phrase;
    };

    this.genPassphrase = () => {
        if (this.words.length === 0) {
            $.get("/dictionary/" + this.dictionary)
            .then((response) => {
                this.words = response.split("\n").filter((w: string) => {
                    return w.length >= 5;
                });
                console.log(`Read ${this.words.length} words from dictionary`);
                this.entry.password = this.genPassphraseHelper(this.words, this.numWords);
                this.showPassword();
            });
        } else {
            console.log("Dictionary already loaded");
            this.entry.password = this.genPassphraseHelper(this.words, this.numWords);
            this.showPassword();
        }
    };

    /**
     * Generate the character set from which to pick for the password
     */
    this.genCharSet = () => {
        this.charSet = [];
        for (let i = "a".charCodeAt(0); i <= "z".charCodeAt(0); i++) {
            this.charSet.push(String.fromCharCode(i));
        }
        for (let i = "A".charCodeAt(0); i <= "Z".charCodeAt(0); i++) {
            this.charSet.push(String.fromCharCode(i));
        }
        for (let i = "0".charCodeAt(0); i <= "9".charCodeAt(0); i++) {
            this.charSet.push(String.fromCharCode(i));
        }
        if (this.useSpecialChars) {
            for (let i = "!".charCodeAt(0); i <= "/".charCodeAt(0); i++) {
                this.charSet.push(String.fromCharCode(i));
            }
        }
    };

    /**
     * Generate a random password from the character set
     */
    this._genPassword = () => {
        if (this.charSet.length === 0) {
            this.genCharSet();
        }
        const passArray: string[] = [];
        for (let i = 0; i < this.passwordLength; i++) {
            passArray[i] = this.charSet[randInt(0, this.charSet.length)];
        }
        this.entry.password = passArray.join("");
        // show newly generated password
        this.showPassword();
    };

    this.genPassword = () => {
        if (this.passwordGenMode === "password") {
            this._genPassword();
        } else {
            this.genPassphrase();
        }
    };

    this.showPassword = (): void => {
        // a wrapper around my somewhat convoluted function
        this.passwordIsVisible = false;
        this.showHidePassword(null);
    };

    /**
     * This is a very dirty hack to actually display the contents of the password field
     */
    this.showHidePassword = (e: Event) => {
        const $elem = $("#password");
        if (this.passwordIsVisible) {
            // hide it
            $elem.attr("type", "password");
            this.passwordIsVisible = false;
        } else {
            // show it
            $elem.attr("type", "text");
            this.passwordIsVisible = true;
        }
    };

    /**
     * Called to submit form data to server
     * Creates a new entry
     * On success does a redirect
     */
    this.createNew = (e: Event): boolean => {
        e.preventDefault();
        const data = Utils.getFormData(e.target as HTMLElement) as ICreateEntryForm;
        pzAPI.createEntry(data)
        .done((response) => {
            window.location.href = "/entries/done_new/" + data.account;
        }).catch((obj, textStatus, textCode) => {
            console.log(obj);
            console.log(textStatus);
            console.log(textCode);
        });
        return false;
    };

    this.getEntryID = (): number => {
        const components = window.location.href.split("/");
        return Number(components[components.length - 1]);
    };

    this.makeEdit = (e: Event): boolean => {
        e.preventDefault();
        const data = Utils.getFormData(e.target as HTMLElement) as IEditEntryForm;
        const entryId = this.getEntryID();
        pzAPI.editEntry(entryId, data)
        .done((response) => {
            window.location.href = "/entries/done_edit/" + data.account;
        }).catch((obj, textStatus, textCode) => {
            console.log(obj);
            console.log(textStatus);
            console.log(textCode);
        });
        return false;
    };

    this.changeLen = (diff: number) => {
        const elem = $("#passLen");
        const len = Number(elem.text());
        elem.text(len + diff);
    };

    this.changePhraseLen = (diff: number) => {
        const elem = $("#phraseLen");
        const len = Number(elem.text());
        if (len + diff > 0 && len + diff <= this.maxNumWords) {
            elem.text(len + diff);
        }
    };

    this.togglePasswordGen = (on: boolean) => {
        if (on) {
            $("#len-container").show();
            $("#gen-pass-btn").prop({ disabled: false });
        } else {
            $("#len-container").hide();
            $("#gen-pass-btn").prop({ disabled: true });
        }
    };

    this.toggleUseSpecialChars = (e: Event) => {
        this.useSpecialChars = !this.useSpecialChars;
    };

    // type = any because it's a specific type of event
    this._onClip = (e: any) => {
        e.clearSelection();
        // typescript complaining about jquery tooltip
        const $elem = $(e.trigger) as any;
        // create the tooltip
        $elem.tooltip({
            "container": "body",
            "animation": true,
            "placement": "bottom",
            "title": "Copied to clipboard!",
            "trigger": "manual"
        });
        // activate the tooltip
        $elem.tooltip("show");
        window.setTimeout(() => {
            // hide the tooltip after a delay
            $elem.tooltip("hide");
        }, 3000);
    };

    /**
     * Called by ng-init on the page
     */
    this.init = (entry: IExistingEntry | null) => {
        if (entry) {
            this.entry = entry;
        }
        console.log(entry);

        // init clip button
        const clipboard = new Clipboard(".copy-pwd-btn");
        clipboard.on("success", this._onClip);

        // set up the logout timer
        this.timer = new LogoutTimer();
        this.timer.startLogoutTimer();
        $("form").click(() => {
            this.timer.resetLogoutTimer();
        });
        $("form").keydown(() => {
            this.timer.resetLogoutTimer();
        });
        window.onfocus = () => {
            this.timer.checkLogoutTimer();
        };
    };
};

let app = angular.module("PassZero", [])
    .controller("PassZeroCtrl", NewCtrl);
// window.app = app;

//export { NewCtrl, app };
