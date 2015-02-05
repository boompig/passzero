var screenWidth = $(document).width();
var screenHeight = $(document).height();

function Dots() {
    "use strict";
    this.numDots = 0;
    this.maxDots = 40;

    this.dots = {};
}

function Dot(speed, xDir, yDir) {
    "use strict";
    this.speed = speed;
    this.xDir = xDir;
    this.yDir = yDir;
}

function randomPos() {
    // don't spawn in the middle
    "use strict";
    var stdDev = screenWidth / 5.0;
    var x = screenWidth / 2;
    var y = screenHeight / 2;
    do {
        x = Math.random() * screenWidth;
        y = Math.random() * screenHeight;
    } while (Math.abs(screenWidth / 2 - x) < stdDev);
    return [x, y];
}

Dots.prototype.moveDots = function (index) {
    "use strict";
    var dot = $("#dot-%d", index);
};

Dots.prototype.spawn = function () {
    "use strict";

    if (this.numDots < this.maxDots) {
        console.log("spawning (%d)", this.numDots + 1);

        var pos = randomPos();
        var dot = $("<div></div>")
                    .addClass("dot")
                    .attr("id", "dot" + this.numDots)
                    .css("top", pos[1])
                    .css("left", pos[0]);

        for (var i = 0; i < this.numDots; i++) {
            //this.moveDot(i);
        }

        dot.hide().appendTo("#hero").fadeIn(4000);
        this.numDots++;

        console.log(pos);
    }

    var that = this;
    window.setTimeout(function() {
        that.spawn();
    }, 1000);
};

$(function () {
    if (screenWidth > 600) {
        var dots = new Dots();
        dots.spawn();
    } else {
        console.log("no pretty effects on mobile");
    }
});
