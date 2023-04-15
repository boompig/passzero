import * as React from 'react';

import { LoggedOutNavbar } from '../components/LoggedOutNavbar';

// import "bootstrap/dist/css/bootstrap.min.css";
import '../common-css/landing.css';

export const LandingMain = () => {
    return <div id="hero-text-container">
        <div id="title-text-container">
            <h1 id="title-text">PassZero</h1>
            <div id="beta-sticker">Beta</div>
        </div>

        <div id="explain-stub">
            Generate strong passwords and store them securely
        </div>

        <div id="btn-container">
            <a id="try-now-btn" className="btn btn-primary"
                href="/signup">Join Now</a>
            <a id="learn-more-btn" className="btn"
                href="/about">Learn More</a>
        </div>
    </div>;
};

export const Landing = () => {
    return <div id="existing-login">
        <div id="hero">
            <LoggedOutNavbar />
            <LandingMain />
        </div>
    </div>;
};

export default Landing;
