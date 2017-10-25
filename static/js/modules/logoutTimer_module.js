/**
 * This logout timer is not very accurate
 * However, it *is* simple. It doesn't need to work perfectly, just well enough to log out after
 * approximately the right amount of time
 */
class LogoutTimer {
	constructor() {
		this.restart = true;
		this.lastActive = null;
		this.val = 0;
		this.maxVal = 4 * 60;

		this.reset = this.reset.bind(this);
		this.start = this.start.bind(this);
		this.check = this.check.bind(this);
		this.logout = this.logout.bind(this);
	}

	reset() {
		this.restart = true;
		this.lastActive = new Date();
		console.log("[LogoutTimer] reset");
	}

	start() {
		if(this.lastActive === null) {
			this.lastActive = new Date();
		}
		// for debugging
		if(this.val % 10 === 0)
			console.log("[LogoutTimer] " + this.val);
		if(this.restart) {
			console.log("[LogoutTimer] restarting");
			this.val = this.maxVal;
			this.restart = false;
		} else {
			if(this.val <= 0) {
				this.logout();
			} else {
				this.val--;
			}
		}
		window.setTimeout(() => {
			this.start();
		}, 1000);
	}

	check() {
		const now = new Date();
		const delta = (now.getTime() - this.lastActive.getTime());
		if (delta > (1000 * this.maxVal)) {
			this.logout();
		}
	}

	logout() {
		window.location.href = "/logout";
	}
}

if(typeof module !== "undefined" && module.exports) {
	module.exports = LogoutTimer;
}
