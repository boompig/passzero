/// <reference types="jquery" />
/// <reference types="angular" />
/// <reference types="clipboard" />
/// <reference path="./logoutTimer.ts" />
/// <reference path="./interfaces.ts" />


// module imports (tsc doesn't like these)
//import * as $ from "jquery";
//import "bootstrap"; // for jquery tooltip
//import * as Clipboard from "clipboard";
//import { LogoutTimer } from "./LogoutTimer";


/**
 * From this SOF thread:
 * https://stackoverflow.com/questions/985272/selecting-text-in-an-element-akin-to-highlighting-with-your-mouse
 */
function selectText(element: HTMLElement) {
	const doc = document;
	const text = element;
	// typescript hack because createTextRange is IE-only
	if ((doc.body as any).createTextRange) {
		const range = (document.body as any).createTextRange();
		range.moveToElementText(text);
		range.select();
	} else if (window.getSelection) {
		const selection = window.getSelection();
		const range = document.createRange();
		range.selectNodeContents(text);
		selection.removeAllRanges();
		selection.addRange(range);
	}
}

function deselectText() {
	const doc = document;
	// typescript hack because createTextRange is IE-only
	if ((doc.body as any).createTextRange) {
		const range = (document.body as any).createTextRange();
		range.select();
	} else if (window.getSelection) {
		const selection = window.getSelection();
		selection.removeAllRanges();
	}
}

const PassZeroCtrl = function($scope, $location, $http, $window, $timeout) {
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
	this.searchEntries = (q: string | null) => {
		if (q === "" || q === null) {
			return this.entries;
		}
		// make search case-insensitive
		q = q.toLowerCase();
		return this.entries.filter((entry: IEncEntry | IDecEntry) => {
			return (entry.account.toLowerCase().indexOf(q) >= 0 ||
				(!entry.is_encrypted && (entry as IDecEntry).username.toLowerCase().indexOf(q) >= 0));
		});
	};

	this.getEntries = () => {
		const that = this;
		$http.get("/api/v2/entries").then((response) => {
			const entries = response.data;
			console.log("Fetched entries:");
			console.log(entries);
			for (let i = 0; i < entries.length; i++) {
				if (!entries[i].hasOwnProperty("is_encrypted")) {
					entries[i].is_encrypted = false;
				}
				that.entries.push(entries[i]);
			}
			that.loadedEntries = true;
			that.submitSearch();
		});
	};

	this.showHidePass = (event: Event) => {
		console.log(event);
		const $elem = $(event.target).parent().parent().parent().find(".hidden-toggle");
		console.log($elem);
		if ($elem.hasClass("password-hidden")) {
			$elem.removeClass("password-hidden");
			$(event.target).text("Hide");
		} else {
			$elem.addClass("password-hidden");
			$(event.target).text("Show");
		}
	};

	this.submitSearch = () => {
		this.filteredEntries = this.searchEntries(this.search);
	};

	this.editEntry = (idx: number) => {
		console.log(idx);
		$window.location.href = "/edit/" + idx;
	};

	this.deleteEntry = (entry: IEncEntry | IDecEntry) => {
		if (confirm("OK to delete entry for account " + entry.account + "?")) {
			console.log("Deleting entry with ID " + entry.id);
			const data = { csrf_token: this.csrf_token };
			$http.delete("/api/v1/entries/" + entry.id, { params: data })
				.then(() => {
					$window.location.href = "/entries/post_delete/" + entry.account;
				}).catch((obj, textStatus, textCode) => {
					console.log(obj);
					console.log(textStatus);
					console.log(textCode);
				});
		}
	};

	this.decryptEntry = (event: Event, entry: IEncEntry, entryIndex: number) => {
		$http.get("/api/v2/entries/" + entry.id)
			.then((result) => {
				const decEntry = result.data;
				// the result is the new entry
				decEntry.is_encrypted = false;
				//console.log(decEntry);
				console.log(entryIndex);
				// copy in the values from the decrypted entry into the current entry
				for (const field in decEntry) {
					if (decEntry.hasOwnProperty(field)) {
						// alter the passed parameter
						(entry as any)[field] = decEntry[field];
					}
				}
				console.log(entry);
			}).catch((obj, textStatus, textCode) => {
				console.log(obj);
				console.log(textStatus);
				console.log(textCode);
			});
	};

	/**
	 * This method is called when the password is clicked
	 * If the password is showing, hide it (and deselect it)
	 * If the password is not showing, show it (and select it)
	 */
	this.toggleHidden = (entry: IEncEntry | IDecEntry) => {
		const elem = $("#entry-" + entry.id).find(".inner-password")[0];
		if (entry.show) {
			entry.show = false;
			deselectText();
		} else {
			entry.show = true;
			selectText(elem);
		}
	};

	/**
	 * Setting event to any because it's a special kind of event
	 */
	this._onClip = (e: any) => {
		e.clearSelection();
		// typescript is complaining about bootstrap
		const $elem = $(e.trigger) as any;
		// create the tooltip
		($elem as any).tooltip({
			"container": "body",
			"animation": true,
			"placement": "bottom",
			"title": "Copied to clipboard!",
			"trigger": "manual"
		});
		// activate the tooltip
		$elem.tooltip("show");
		$timeout(() => {
			// hide the tooltip after a delay
			$elem.tooltip("hide");
		}, 3000);
	};

	this.init = () => {
		// init clip button
		const clipboard = new Clipboard(".copy-pwd-btn");
		clipboard.on("success", this._onClip);
		const timer = new LogoutTimer();
		timer.startLogoutTimer();
		$("#entry-container").click(() => {
			timer.resetLogoutTimer();
		});
		$window.onfocus = () => {
			timer.checkLogoutTimer();
		};
		// fill in CSRF token value
		this.csrf_token = $("#csrf_token").val();
		this.getEntries();
	};

	this.init();
};

const app = angular.module("PassZero", [])
	.controller("PassZeroCtrl", PassZeroCtrl);

//export { app, PassZeroCtrl, showHidePass };
