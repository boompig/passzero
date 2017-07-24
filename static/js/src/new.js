/* global $, pzAPI, getFormData, LogoutTimer */
/* exported showHideSettings, genPassphrase, genPassword, createNew, makeEdit, changeLen, changePhraseLen, toggleSpecialChars, showHidePassword */

/* for passphrase generation */
var dictionary = "common.txt";

var timer = null;

var pzState = {
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

/**
 * This is pseudo-react
 * It only renders based on state
 * Make changes to the DOM based on JQuery
 *
 * @param changedState		-  ignored
 *
 * Real parameter is global state pzState
 *
 *
 * NOTE:
 * React is much faster than this because it maintains only state.
 * It then efficiently computes delta between states and only changes that which needs to change.
 *
 *
 */
function renderState(changedState) {
	//TODO use changedState

	// settings container itself
	if(pzState.showSettings) {
		$("#len-container").show();
	} else {
		$("#len-container").hide();
	}

	// password show button
	var $elem = $("#password");
	if (pzState.showPassword === true) {
		$elem.attr("type", "text");
		$("#show-hide-btn").text("Hide");
	} else {
		$elem.attr("type", "password");
		$("#show-hide-btn").text("Show");
	}

	// more password show button
	if(pzState.password === "") {
		$("#show-hide-btn").prop({ "disabled": true });
	} else {
		$("#show-hide-btn").prop({ "disabled": false });
	}

	// password field
	$("#password").val(pzState.password);

	// password generation buttons
	if(pzState.password === "") {
		$(".pass-gen-btn").prop({ "disabled": true });
	} else {
		$(".pass-gen-btn").prop({ "disabled": false });
	}

	// gen special characters UI thingy
	if (pzState.useSpecialChars) {
		$("#toggle-special-chars-btn").addClass("active");
	} else {
		$("#toggle-special-chars-btn").removeClass("active");
	}

	// password gen length
	$("#password-length").text(pzState.passwordLength);
	if(pzState.passwordLength === 0) {
		$("#password-minus-btn").prop({ "disabled": true });
	} else {
		$("#password-minus-btn").prop({ "disabled": false });
	}

	// passphrase gen length
	$("#passphrase-length").text(pzState.passphraseLength);
	if(pzState.passphraseLength === 0) {
		$("#passphrase-minus-btn").prop({ "disabled": true });
	} else {
		$("#passphrase-minus-btn").prop({ "disabled": false });
	}
}

/**
 * React-lite using JQuery
 *
 * Set a state, then only perform changes to the affected components
 */
function setState(changes, callback) {
	if(typeof(changes) !== "object") {
		console.error("changes must be object");
		return;
	}
	// apply the changes
	for(var k in changes) {
		pzState[k] = changes[k];
	}
	// render only the changes
	renderState(changes);
	if(callback) {
		callback();
	}
}

/**
 * Get a random integer in interval [a, b)
 */
function randInt(a, b) {
	return Math.floor(Math.random() * (b - a) + a);
}

/**
 * Connected to UI element
 * UI button to show or hide settings
 */
function showHideSettings(event) {
	setState({"showSettings": !pzState.showSettings});
}

function _genPassphraseHelper() {
	"use strict";
	console.log("generating passphrase of length " + pzState.passphraseLength);
	var phrase = "", index, word;
	for (var i = 0; i < pzState.passphraseLength; i++) {
		index = Math.floor(Math.random() * pzState.words.length);
		word = pzState.words[index];
		word = word[0].toUpperCase() + word.substr(1);
		phrase += word;
	}
	setState({
		"password": phrase,
		"showPassword": true
	});
}

function loadDictionary(callback) {
	console.log("Loading dictionary...");
	return $.get("/dictionary/" + dictionary)
		.then(function (response) {
			var finalWords = response.split("\n").filter(function (w) {
				return w.length >= 5;
			});
			setState({"words": finalWords}, function() {
				console.log("Loaded " + pzState.words.length + " words for passphrase generation");
				callback();
			});
		});
}

/**
 * Connected to UI element
 * Generate a new passphrase
 */
function genPassphrase(event) {
	"use strict";
	if(pzState.dictionaryIsLoaded) {
		_genPassphraseHelper();
	} else {
		loadDictionary(function() {
			_genPassphraseHelper();
		});
	}
}

function loadCharset(callback) {
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
	if (pzState.useSpecialChars) {
		for (i = "!".charCodeAt(0); i <= "/".charCodeAt(0); i++) {
			chars.push(String.fromCharCode(i));
		}
	}
	setState({
		"charsetLoaded": true,
		"charset": chars
	}, callback);
}

function _genPasswordHelper(charset) {
	var passArray = [];
	for (var i = 0; i < pzState.passwordLength; i++) {
		passArray[i] = charset[randInt(0, charset.length)];
	}
	var pass = passArray.join("");
	setState({
		"password": pass,
		"showPassword": true
	});
}

/**
 * Generate a random password
 * Connected to UI element
 */
function genPassword(event) {
	"use strict";
	if(pzState.charsetLoaded) {
		_genPasswordHelper(pzState.charset);
	} else {
		loadCharset(function() {
			_genPasswordHelper(pzState.charset);
		});
	}
}

/**
 * Show or hide current password
 * Connects with the HTML elements
 */
function showHidePassword(event) {
	setState({ "showPassword": !pzState.showPassword });
}

/**
 * Called to submit form data to server
 * Creates a new entry
 * On success does a redirect
 */
function createNew (e) {
	"use strict";
	e.preventDefault();
	var data = getFormData(e.target);
	pzAPI.createEntry(data, data.csrf_token)
		.then(function() {
			window.location.href = "/entries/done_new/" + data.account;
		}).catch(function (obj, textStatus, textCode) {
			console.log(obj);
			console.log(textStatus);
			console.log(textCode);
		});
	return false;
}

function getEntryID() {
	var components = window.location.href.split("/");
	return components[components.length - 1];
}

/**
 * Connected to UI element
 */
function makeEdit (e) {
	"use strict";
	e.preventDefault();
	var data = getFormData(e.target);
	var entry_id = getEntryID();
	pzAPI.editEntry(entry_id, data, data.csrf_token)
		.then(function() {
			window.location.href = "/entries/done_edit/" + data.account;
		});
	return false;
}

/**
 * Connected to UI element
 * Change the number of characters to use for generating passwords
 */
function changeLen(diff) {
	"use strict";
	setState({ "passwordLength": Math.max(pzState.passwordLength + diff, 0) });
}

/**
 * Connected to UI element
 */
function changePhraseLen(diff) {
	"use strict";
	setState({ "passphraseLength": Math.max(pzState.passphraseLength + diff, 0) });
}

/**
 * Connected to UI element
 */
function toggleSpecialChars(event) {
	"use strict";
	setState({
		"useSpecialChars": !pzState.useSpecialChars,
		// reset whether the character set has been loaded
		"charsetLoaded": false
	});
}

$(function() {
	"use strict";
	
	// set the initial state from the template
	setState({
		"password": $("#password").val(),
		"passwordLength": Number($("#password-length").text()),
		"passphraseLength": Number($("#passphrase-length").text())
	});

	$("#password").keyup(function (e) {
		var pass = $(e.target).val();
		setState({ "password": pass });
	});

	// set in globals (declared at top)
	timer = new LogoutTimer();
	timer.startLogoutTimer();
	$("form").click(function () {
		timer.resetLogoutTimer();
	});
	$("form").keydown(function() {
		timer.resetLogoutTimer();
	});
	window.onfocus = function () {
		timer.checkLogoutTimer();
	};
});
