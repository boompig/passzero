/* global $, Clipboard, angular, LogoutTimer */
/* exported showHidePass, app */

/**
 * From this SOF thread:
 * https://stackoverflow.com/questions/985272/selecting-text-in-an-element-akin-to-highlighting-with-your-mouse
 */
function selectText(element) {
	"use strict";
	var doc = document;
	var text = element;
	var range, selection;
	if (doc.body.createTextRange) {
		range = document.body.createTextRange();
		range.moveToElementText(text);
		range.select();
	} else if (window.getSelection) {
		selection = window.getSelection();
		range = document.createRange();
		range.selectNodeContents(text);
		selection.removeAllRanges();
		selection.addRange(range);
	}
}

function deselectText () {
	var doc = document, range, selection;
	if (doc.body.createTextRange) {
		range = document.body.createTextRange();
		range.select();
	} else if (window.getSelection) {
		selection = window.getSelection();
		selection.removeAllRanges();
	}
}

function showHidePass(event) {
	"use strict";
	var elem = $(event.target).parent().parent().parent().find(".hidden-toggle");
	if (elem.hasClass("password-hidden")) {
		elem.removeClass("password-hidden");
		$(event.target).text("Hide");
	} else {
		elem.addClass("password-hidden");
		$(event.target).text("Show");
	}
}

/* polyfill */
String.prototype.endswith = function (s) {
	var idx = this.lastIndexOf(s);
	return idx >= 0 && idx == this.length - s.length;
};

/**
 * do something a little more component-based
 */

var PassZeroCtrl = function ($scope, $location, $http, $window, $timeout) {
	this.search = null;
	this.entries = [];
	this.filteredEntries = [];
	/**
	 * CSRF token is stored in a hidden field in the HTML by the server.
	 * This field is filled at load
	 */
	this.csrf_token = null;

	this.loadedEntries = false;

	/**
	 * Given a query, return all entry objects matching that query.
	 * Match is not case sensitive
	 * Match is done on account name or username
	 *
	 * NOTE: if you're thinking of tweaking the performance here, the real bottleneck is the draw
	 * This can be seen because the longest operation is on backspace which is a trivial case in the function below
	 *
	 * @return {Array} Return an array of entries
	 */
	this.searchEntries = function (q) {
		if (q === "" || q === null)
			return this.entries;
		// make search case-insensitive
		q = q.toLowerCase();
		return this.entries.filter(function(entry) {
			return (entry.account.toLowerCase().indexOf(q) >= 0 ||
				(!entry.is_encrypted && entry.username.toLowerCase().indexOf(q) >= 0));
		});
	};

	this.getEntries = function () {
		var that = this;
		$http.get("/api/v2/entries").then(function (response) {
			var entries = response.data;
			console.log("Fetched entries:");
			console.log(entries);
			for (var i = 0; i < entries.length; i++) {
				if(!entries[i].hasOwnProperty("is_encrypted")) {
					entries[i].is_encrypted = false;
				}
				that.entries.push(entries[i]);
			}
			that.loadedEntries = true;
			that.submitSearch();
		});
	};

	this.submitSearch = function () {
		this.filteredEntries = this.searchEntries(this.search);
	};

	this.editEntry = function (idx) {
		console.log(idx);
		$window.location.href = "/edit/" + idx;
	};

	this.deleteEntry = function (entry) {
		if (confirm("OK to delete entry for account " + entry.account + "?")) {
			console.log("Deleting entry with ID " + entry.id);
			var data = { csrf_token: this.csrf_token };
			$http.delete("/api/v1/entries/" + entry.id, { params: data })
				.then(function () {
					$window.location.href = "/entries/post_delete/" + entry.account;
				}).catch(function (obj, textStatus, textCode) {
					console.log(obj);
					console.log(textStatus);
					console.log(textCode);
				});
		}
	};

	this.decryptEntry = function(event, entry, entryIndex) {
		//var that = this;
		//console.log(event);
		//console.log(entry.id);
		$http.get("/api/v2/entries/" + entry.id)
			.then(function(result) {
				var decEntry = result.data;
				// the result is the new entry
				decEntry.is_encrypted = false;
				//console.log(decEntry);
				console.log(entryIndex);
				// copy in the values from the decrypted entry into the current entry
				for(var field in decEntry) {
					if(decEntry.hasOwnProperty(field)) {
						// alter the passed parameter
						entry[field] = decEntry[field];
					}
				}
				console.log(entry);
			}).catch(function (obj, textStatus, textCode) {
				console.log(obj);
				console.log(textStatus);
				console.log(textCode);
			});
	};

	this.toggleHidden = function (entry) {
		var elem = $("#entry-" + entry.id).find(".inner-password")[0];
		if (entry.show) {
			entry.show = false;
			deselectText();
		} else {
			entry.show = true;
			selectText(elem);
		}
	};

	this._onClip = function(e) {
		e.clearSelection();
		//console.log(e.trigger);
		var elem = $(e.trigger);
		// create the tooltip
		elem.tooltip({
			"container": "body",
			"animation": true,
			"placement": "bottom",
			"title": "Copied to clipboard!",
			"trigger": "manual"
		});
		// activate the tooltip
		elem.tooltip("show");
		$timeout(function() {
			// hide the tooltip after a delay
			elem.tooltip("hide");
		}, 3000);
	};

	this.init = function () {
		// init clip button
		var clipboard = new Clipboard(".copy-pwd-btn");
		clipboard.on("success", this._onClip);
		var timer = new LogoutTimer();
		timer.startLogoutTimer();
		$("#entry-container").click(function() {
			timer.resetLogoutTimer();
		});
		$window.onfocus = function () {
			timer.checkLogoutTimer();
		};
		// fill in CSRF token value
		this.csrf_token = $("#csrf_token").val();
		this.getEntries();
	};

	this.init();
};

var app = angular.module("PassZero", [])
	.controller("PassZeroCtrl", PassZeroCtrl);
