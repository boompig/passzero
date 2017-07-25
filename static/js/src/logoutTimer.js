var LogoutTimer = (function () {
    function LogoutTimer() {
        this.restart = true;
        this.lastActive = null;
        this.val = 0;
        this.maxVal = 4 * 60;
    }
    LogoutTimer.prototype.resetLogoutTimer = function () {
        "use strict";
        this.restart = true;
        this.lastActive = new Date();
        console.log("restart");
    };
    LogoutTimer.prototype.startLogoutTimer = function () {
        "use strict";
        var _this = this;
        if (this.lastActive === null) {
            this.lastActive = new Date();
        }
        // for debugging
        if (this.val % 10 === 0)
            console.log(this.val);
        if (this.restart) {
            console.log("restarting");
            this.val = this.maxVal;
            this.restart = false;
        }
        else {
            if (this.val <= 0) {
                this.logout();
            }
            else {
                this.val--;
            }
        }
        window.setTimeout(function () {
            _this.startLogoutTimer();
        }, 1000);
    };
    LogoutTimer.prototype.checkLogoutTimer = function () {
        "use strict";
        var now = new Date();
        var delta = (now.getTime() - this.lastActive.getTime());
        if (delta > (1000 * this.maxVal)) {
            this.logout();
        }
    };
    LogoutTimer.prototype.logout = function () {
        window.location.href = "/logout";
    };
    return LogoutTimer;
}());
