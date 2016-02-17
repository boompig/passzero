function showHidePass(event) {
    "use strict";
    var elem = $(event.target).parent().parent().find(".hidden-toggle");
    if (elem.hasClass("password-hidden")) {
        elem.removeClass("password-hidden");
        $(event.target).text("Hide");
    } else {
        elem.addClass("password-hidden");
        $(event.target).text("Show");
    }
}

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

/* polyfill */
String.prototype.endswith = function (s) {
    var idx = this.lastIndexOf(s);
    return idx >= 0 && idx == this.length - s.length;
};

var PassZeroCtrl = function ($scope, $location, $http) {
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
     */
    this.searchEntries = function (q) {
        if (q === "" || q === null)
            return this.entries;
        q = q.toLowerCase();
        var entry;
        var l = [];
        for (var i = 0; i < this.entries.length; i++) {
            entry = this.entries[i];
            if (entry.account.toLowerCase().indexOf(q) >= 0 ||
                entry.username.toLowerCase().indexOf(q) >= 0) {
                l.push(entry);
            }
        }
        return l;
    };

    this.getEntries = function () {
        var that = this;
        $http.get("/api/entries").success(function (response) {
            console.log(response);
            for (var i = 0; i < response.length; i++) {
                that.entries.push(response[i]);
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
        window.location.href = "/edit/" + idx;
    };

    this.deleteEntry = function (entry) {
        if (confirm("OK to delete entry for account " + entry.account + "?")) {
            console.log("Deleting entry with ID " + entry.id);
            var data = { csrf_token: this.csrf_token };
            $http.delete("/api/entries/" + entry.id, { params: data })
            .success(function (result) {
                window.location.href = "/entries/post_delete/" + entry.account;
            }).error(function (obj, textStatus, textCode) {
                console.log(obj);
                console.log(textStatus);
                console.log(textCode);
            });
        }
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

    this.init = function () {
        var timer = new LogoutTimer();
        timer.startLogoutTimer();
        $("#entry-container").click(function() {
            timer.resetLogoutTimer();
        });
        window.onfocus = function () {
            timer.checkLogoutTimer();
        };
        // fill in CSRF token value
        this.csrf_token = $("#csrf_token").val();
        this.getEntries();
    };

    this.init();
};

var app = angular.module("PassZero", ["ngAnimate"])
    .controller("PassZeroCtrl", PassZeroCtrl);
