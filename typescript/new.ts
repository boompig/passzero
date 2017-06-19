// provided externally via CDN
declare let $: any;
declare let angular: any;

// provided externally
declare let Utils: any;
declare let pzAPI: any;
declare let LogoutTimer: any;

/**
 * Get a random integer in interval [a, b)
 */
function randInt(a, b) {
    return Math.floor(Math.random() * (b - a) + a);
}

interface ICreateEntryForm {
    account: string;
    username: string;
    password: string;
    extra: string;
    csrf_token: string;
}

interface IEntry {
    account: string;
    username: string;
    password: string;
    extra: string;
    id: number;
    version: number;
}

var NewCtrl = function() {
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

    this.showHideSettings = function() {
        this.showSettings = !this.showSettings;
    };

    /**
     * Return the passphrase that has been generated from the given corpus of words
     */
    this.genPassphraseHelper = function(words: Array<string>, numWords: number): string {
        let phrase = "", index, word, i;
        for (i = 0; i < numWords; i++) {
            let word = words[randInt(0, words.length)];
            word = word[0].toUpperCase() + word.substr(1);
            phrase += word;
        }
        return phrase;
    }

    this.genPassphrase = function() {
        if (this.words.length === 0) {
            $.get("/dictionary/" + this.dictionary)
            .then((response) => {
                this.words = response.split("\n").filter((w) => {
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
    this.genCharSet = function() {
        this.charSet = [];
        let i;
        for (i = "a".charCodeAt(0); i <= "z".charCodeAt(0); i++) {
            this.charSet.push(String.fromCharCode(i));
        }
        for (i = "A".charCodeAt(0); i <= "Z".charCodeAt(0); i++) {
            this.charSet.push(String.fromCharCode(i));
        }
        for (i = "0".charCodeAt(0); i <= "9".charCodeAt(0); i++) {
            this.charSet.push(String.fromCharCode(i));
        }
        if (this.useSpecialChars) {
            for (i = "!".charCodeAt(0); i <= "/".charCodeAt(0); i++) {
                this.charSet.push(String.fromCharCode(i));
            }
        }
    };

    /**
     * Generate a random password from the character set
     */
    this._genPassword = function() {
        if(this.charSet.length === 0) {
            this.genCharSet();
        }
        const passArray: Array<string> = [];
        for (let i = 0; i < this.passwordLength; i++) {
            passArray[i] = this.charSet[randInt(0, this.charSet.length)];
        }
        this.entry.password = passArray.join("");
        // show newly generated password
        this.showPassword();
    };

    this.genPassword = function() {
        if(this.passwordGenMode === "password") {
            this._genPassword();
        } else {
            this.genPassphrase()
        }
    };

    this.showPassword = function() {
        // a wrapper around my somewhat convoluted function
        this.passwordIsVisible = false;
        this.showHidePassword(null);
    };

    /**
     * This is a very dirty hack to actually display the contents of the password field
     */
    this.showHidePassword = function(e) {
        let $elem = $("#password");
        if (this.passwordIsVisible) {
            // hide it
            $elem.attr("type", "password");
            this.passwordIsVisible = false;
        } else {
            // show it
            $elem.attr("type", "text");
            this.passwordIsVisible = true;
        }
    }

    /**
     * Called to submit form data to server
     * Creates a new entry
     * On success does a redirect
     */
    this.createNew = function(e: Event) {
        e.preventDefault();
        const url = $(e.target).attr("action");
        const data: ICreateEntryForm = Utils.getFormData(e.target);
        pzAPI.createEntry(data, data.csrf_token)
        .then(function(response) {
            window.location.href = "/entries/done_new/" + data.account;
        }).catch((obj, textStatus, textCode) => {
            console.log(obj);
            console.log(textStatus);
            console.log(textCode);
        });
        return false;
    };

    this.getEntryID = function(): number {
        const components = window.location.href.split("/");
        return Number(components[components.length - 1]);
    };

    this.makeEdit = function(e) {
        "use strict";
        e.preventDefault();
        var data = Utils.getFormData(e.target);
        var entry_id = this.getEntryID();
        pzAPI.editEntry(entry_id, data, data.csrf_token)
        .then(function(response) {
            window.location.href = "/entries/done_edit/" + data.account;
        });
        return false;
    };

    this.changeLen = function(diff) {
        var elem = $("#passLen");
        var len = Number(elem.text());
        elem.text(len + diff);
    };

    this.changePhraseLen = function(diff) {
        var elem = $("#phraseLen");
        var len = Number(elem.text());
        if (len + diff > 0 && len + diff <= this.maxNumWords) {
            elem.text(len + diff);
        }
    };

    this.togglePasswordGen = function(on) {
        if (on) {
            $("#len-container").show();
            $("#gen-pass-btn").prop({ disabled: false });
        } else {
            $("#len-container").hide();
            $("#gen-pass-btn").prop({ disabled: true });
        }
    };

    this.toggleUseSpecialChars = function(e: Event) {
        this.useSpecialChars = !this.useSpecialChars;
    };

    /**
     * Called by ng-init on the page
     */
    this.init = function(entry: IEntry | null) {
        if(entry) {
            this.entry = entry;
        }
        console.log(entry);

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

var app = angular.module("PassZero", [])
    .controller("PassZeroCtrl", NewCtrl);
