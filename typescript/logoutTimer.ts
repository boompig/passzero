class LogoutTimer {
    restart: boolean;
    lastActive: Date | null;
    val: number;
    maxVal: number;

    constructor() {
        this.restart = true;
        this.lastActive = null;
        this.val = 0;
        this.maxVal = 4 * 60;
    }

    resetLogoutTimer() {
        this.restart = true;
        this.lastActive = new Date();
        console.log("[LogoutTimer] reset");
    };

    startLogoutTimer () {
        if (this.lastActive === null) {
            this.lastActive = new Date();
        }

        // for debugging
        if (this.val % 10 === 0) console.log(this.val);

        if (this.restart) {
            console.log("restarting");
            this.val = this.maxVal;
            this.restart = false;
        } else {
            if (this.val <= 0) {
                this.logout();
            } else {
                this.val--;
            }
        }
        window.setTimeout(() => {
            this.startLogoutTimer();
        }, 1000);
    };

    checkLogoutTimer () {
        const now: Date = new Date();
        const diff = now.valueOf() - this.lastActive.valueOf();
        if (diff > (1000 * this.maxVal)) {
            this.logout();
        }
    };

    logout () {
        window.location.href = "/logout";
    };
}
