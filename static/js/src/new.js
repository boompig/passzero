/**
 * Get a random integer in interval [a, b)
 */
function randInt(a, b) {
    return Math.floor(Math.random() * (b - a) + a);
}
var NewEntry = (function () {
    function NewEntry() {
    }
    /**
     * This is pseudo-react
     * It only renders based on state
     * Make changes to the DOM based on JQuery
     *
     * @param changedState		-  ignored
     *
     * Real parameter is global state NewEntry.state
     *
     *
     * NOTE:
     * React is much faster than this because it maintains only state.
     * It then efficiently computes delta between states and only changes that which needs to change.
     *
     *
     */
    NewEntry.renderState = function (changedState) {
        //TODO use changedState
        // settings container itself
        if (NewEntry.state.showSettings) {
            $("#len-container").show();
        }
        else {
            $("#len-container").hide();
        }
        // password show button
        var $elem = $("#password");
        if (NewEntry.state.showPassword === true) {
            $elem.attr("type", "text");
            $("#show-hide-btn").text("Hide");
        }
        else {
            $elem.attr("type", "password");
            $("#show-hide-btn").text("Show");
        }
        // more password show button
        if (NewEntry.state.password === "") {
            $("#show-hide-btn").prop({ "disabled": true });
        }
        else {
            $("#show-hide-btn").prop({ "disabled": false });
        }
        // password field
        $("#password").val(NewEntry.state.password);
        // password generation buttons
        if (NewEntry.state.password === "") {
            $(".pass-gen-btn").prop({ "disabled": true });
        }
        else {
            $(".pass-gen-btn").prop({ "disabled": false });
        }
        // gen special characters UI thingy
        if (NewEntry.state.useSpecialChars) {
            $("#toggle-special-chars-btn").addClass("active");
        }
        else {
            $("#toggle-special-chars-btn").removeClass("active");
        }
        // password gen length
        $("#password-length").text(NewEntry.state.passwordLength);
        if (NewEntry.state.passwordLength === 0) {
            $("#password-minus-btn").prop({ "disabled": true });
        }
        else {
            $("#password-minus-btn").prop({ "disabled": false });
        }
        // passphrase gen length
        $("#passphrase-length").text(NewEntry.state.passphraseLength);
        if (NewEntry.state.passphraseLength === 0) {
            $("#passphrase-minus-btn").prop({ "disabled": true });
        }
        else {
            $("#passphrase-minus-btn").prop({ "disabled": false });
        }
    };
    /**
     * React-lite using JQuery
     *
     * Set a state, then only perform changes to the affected components
     */
    NewEntry.setState = function (changes, callback) {
        if (typeof (changes) !== "object") {
            throw "changes must be object";
        }
        // apply the changes
        for (var k in changes) {
            NewEntry.state[k] = changes[k];
        }
        // render only the changes
        NewEntry.renderState(changes);
        if (callback) {
            callback();
        }
    };
    /**
    * Connected to UI element
    * UI button to show or hide settings
    */
    NewEntry.showHideSettings = function (event) {
        NewEntry.setState({ "showSettings": !NewEntry.state.showSettings });
    };
    NewEntry._genPassphraseHelper = function () {
        "use strict";
        console.log("generating passphrase of length " + NewEntry.state.passphraseLength);
        var phrase = "", index, word;
        for (var i = 0; i < NewEntry.state.passphraseLength; i++) {
            index = Math.floor(Math.random() * NewEntry.state.words.length);
            word = NewEntry.state.words[index];
            word = word[0].toUpperCase() + word.substr(1);
            phrase += word;
        }
        NewEntry.setState({
            "password": phrase,
            "showPassword": true
        });
    };
    NewEntry.loadDictionary = function (callback) {
        console.log("Loading dictionary...");
        return $.get("/dictionary/" + this.dictionary)
            .then(function (response) {
            var finalWords = response.split("\n").filter(function (w) {
                return w.length >= 5;
            });
            NewEntry.setState({ "words": finalWords }, function () {
                console.log("Loaded " + NewEntry.state.words.length + " words for passphrase generation");
                callback();
            });
        });
    };
    /**
    * Connected to UI element
    * Generate a new passphrase
    */
    NewEntry.genPassphrase = function (event) {
        "use strict";
        if (NewEntry.state.dictionaryIsLoaded) {
            NewEntry._genPassphraseHelper();
        }
        else {
            NewEntry.loadDictionary(function () {
                NewEntry._genPassphraseHelper();
            });
        }
    };
    NewEntry.loadCharset = function (callback) {
        var i;
        var chars = [];
        for (i = "a".charCodeAt(0); i <= "z".charCodeAt(0); i++) {
            chars.push(String.fromCharCode(i));
        }
        for (i = "A".charCodeAt(0); i <= "Z".charCodeAt(0); i++) {
            chars.push(String.fromCharCode(i));
        }
        for (i = "0".charCodeAt(0); i <= "9".charCodeAt(0); i++) {
            chars.push(String.fromCharCode(i));
        }
        if (NewEntry.state.useSpecialChars) {
            for (i = "!".charCodeAt(0); i <= "/".charCodeAt(0); i++) {
                chars.push(String.fromCharCode(i));
            }
        }
        NewEntry.setState({
            "charsetLoaded": true,
            "charset": chars
        }, callback);
    };
    NewEntry._genPasswordHelper = function (charset) {
        var passArray = [];
        for (var i = 0; i < NewEntry.state.passwordLength; i++) {
            passArray[i] = charset[randInt(0, charset.length)];
        }
        var pass = passArray.join("");
        NewEntry.setState({
            "password": pass,
            "showPassword": true
        });
    };
    /**
    * Generate a random password
    * Connected to UI element
    */
    NewEntry.genPassword = function (event) {
        "use strict";
        var _this = this;
        if (this.state.charsetLoaded) {
            this._genPasswordHelper(NewEntry.state.charset);
        }
        else {
            this.loadCharset(function () {
                _this._genPasswordHelper(NewEntry.state.charset);
            });
        }
    };
    /**
    * Show or hide current password
    * Connects with the HTML elements
    */
    NewEntry.showHidePassword = function (event) {
        NewEntry.setState({ "showPassword": !NewEntry.state.showPassword });
    };
    /**
    * Called to submit form data to server
    * Creates a new entry
    * On success does a redirect
    */
    NewEntry.createNew = function (e) {
        "use strict";
        e.preventDefault();
        var data = Utils.getFormData(e.target);
        pzAPI._createEntry(data, data.csrf_token)
            .then(function () {
            window.location.href = "/entries/done_new/" + data.account;
        })["catch"](function (obj, textStatus, textCode) {
            console.log(obj);
            console.log(textStatus);
            console.log(textCode);
        });
        return false;
    };
    NewEntry.getEntryID = function () {
        var components = window.location.href.split("/");
        return Number(components[components.length - 1]);
    };
    /**
    * Connected to UI element
    */
    NewEntry.makeEdit = function (e) {
        "use strict";
        e.preventDefault();
        var data = Utils.getFormData(e.target);
        var entry_id = this.getEntryID();
        pzAPI._editEntry(entry_id, data, data.csrf_token)
            .then(function () {
            window.location.href = "/entries/done_edit/" + data.account;
        });
        return false;
    };
    /**
    * Connected to UI element
    * Change the number of characters to use for generating passwords
    */
    NewEntry.changeLen = function (diff) {
        "use strict";
        NewEntry.setState({ "passwordLength": Math.max(NewEntry.state.passwordLength + diff, 0) });
    };
    /**
    * Connected to UI element
    */
    NewEntry.changePhraseLen = function (diff) {
        "use strict";
        NewEntry.setState({ "passphraseLength": Math.max(NewEntry.state.passphraseLength + diff, 0) });
    };
    /**
    * Connected to UI element
    */
    NewEntry.toggleSpecialChars = function (event) {
        "use strict";
        NewEntry.setState({
            "useSpecialChars": !NewEntry.state.useSpecialChars,
            // reset whether the character set has been loaded
            "charsetLoaded": false
        });
    };
    return NewEntry;
}());
/* for passphrase generation */
NewEntry.dictionary = "common.txt";
NewEntry.timer = null;
NewEntry.state = {
    /* UI */
    showSettings: false,
    showPassword: false,
    useSpecialChars: true,
    /* proper state */
    // this refers to the generation length
    passwordLength: 0,
    password: "",
    // this refers to the generation length
    passphraseLength: 0,
    dictionaryIsLoaded: false,
    // this is the loaded list of words for passphrase generation
    words: [],
    // used for password generation
    charsetLoaded: false,
    charset: []
};
$(function () {
    "use strict";
    // set the initial state from the template
    NewEntry.setState({
        "password": $("#password").val(),
        "passwordLength": Number($("#password-length").text()),
        "passphraseLength": Number($("#passphrase-length").text())
    });
    $("#password").keyup(function (e) {
        var pass = $(e.target).val();
        NewEntry.setState({ "password": pass });
    });
    // set in globals (declared at top)
    NewEntry.timer = new LogoutTimer();
    NewEntry.timer.startLogoutTimer();
    $("form").click(function () {
        NewEntry.timer.resetLogoutTimer();
    });
    $("form").keydown(function () {
        NewEntry.timer.resetLogoutTimer();
    });
    window.onfocus = function () {
        NewEntry.timer.checkLogoutTimer();
    };
});
