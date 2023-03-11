import * as React from "react";

// import "bootstrap/dist/css/bootstrap.min.css";
// import "../common/logged-out-navbar.css";

export const LoggedOutNavbar = () => {
    const path = window.location.pathname;
    let navItems;
    if (path === '/') {
        navItems = <>
            <li className="nav-item"><a href="/login">Sign In</a></li>
            <li className="nav-item"><a href="/about">About</a></li>
            <li className="nav-item"><a href="https://github.com/boompig/passzero">Code</a></li>
            <li className="nav-item"><a href="https://github.com/boompig/passzero/issues">Bug Tracker</a></li>
        </>;
    } else {
        navItems = <>
            <li className="nav-item"><a href="/">Home</a></li>
            { (window.location.pathname === '/login') || (window.location.pathname === '/') ?
                <li className="nav-item"><a href="/register">Register</a></li> :
                <li className="nav-item"><a href="/login">Login</a></li> }
            <li className="nav-item"><a href="/about">About</a></li>
        </>;
    }

    return <nav className="navbar" id="logged-out-navbar">
        <ul className="nav-items">
            { navItems }
        </ul>
    </nav>;
};

export default LoggedOutNavbar;