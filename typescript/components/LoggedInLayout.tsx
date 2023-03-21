/**
 * Based on layout-react.jinja2
 */
import * as React from "react";

// import { LoggedInNavbar } from './LoggedInNavbar';

// import './main.css';

export const LoggedInLayout = ({ children }: { children: React.ReactNode }) => {
    return <>
        {/* <header> */}
        {/* <LoggedInNavbar /> */}
        {/* </header> */}
        <main className="container logged-in-main">
            <div className="inner-container">
                { children }
            </div>
        </main>
        {/* <footer>Developed by Daniel Kats</footer> */}
    </>;
};
