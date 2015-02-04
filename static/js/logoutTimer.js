function LogoutTimer() {
    "use strict";
    this.restart = true;
    this.val = 0;
    this.maxVal = 4 * 60;
}

LogoutTimer.prototype.resetLogoutTimer = function () {
    "use strict";
    this.restart = true;
    console.log("restart");
};

LogoutTimer.prototype.startLogoutTimer = function() {
    "use strict";

    // for debugging
    if (this.val % 10 === 0) console.log(this.val);

    if (this.restart) {
        console.log("restarting");
        this.val = this.maxVal;
        this.restart = false;
    } else {
        if (this.val <= 0) {
            // logout
            window.location.href = "/logout";
        } else {
            this.val--;
        }
    }

    var that = this;
    window.setTimeout(function () {
        that.startLogoutTimer();
    }, 1000);
};
