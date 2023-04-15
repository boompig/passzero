/**
 * Based on layout-react.jinja2
 */
import * as React from 'react';

import { AccessTokenProvider } from './AccessTokenProvider';
import { LoggedInNavbar } from './LoggedInNavbar';

import '../common-css/main.css';

export const LoggedInLayout = ({ children }: { children: React.ReactNode }) => {
    return <>
        <header>
            <LoggedInNavbar />
        </header>
        <AccessTokenProvider>
            <main className="container logged-in-main">
                <div className="inner-container">
                    {children}
                </div>
            </main>
        </AccessTokenProvider>
        {/* <footer>Developed by Daniel Kats</footer> */}
    </>;
};
