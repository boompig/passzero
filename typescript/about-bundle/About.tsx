import * as React from "react";
import { FontAwesomeIcon } from '@fortawesome/react-fontawesome';
import { library } from '@fortawesome/fontawesome-svg-core';
import { faHome } from '@fortawesome/free-solid-svg-icons/faHome';
import { faInfoCircle } from '@fortawesome/free-solid-svg-icons/faInfoCircle';
import { faSignInAlt } from '@fortawesome/free-solid-svg-icons/faSignInAlt';
import { faEdit } from '@fortawesome/free-solid-svg-icons/faEdit';
import Navbar from 'react-bootstrap/Navbar';
import Nav from 'react-bootstrap/Nav';
import Container from 'react-bootstrap/Container';

library.add(faHome, faInfoCircle, faSignInAlt, faEdit);

interface INavbarItem {
    /**
     * The path to visit for this item
     */
    path: string;
    /**
     * Easy way for us to select a specific item
     */
    key: string;
    /**
     * The text displayed to the user
     */
    friendlyName: string;
    /**
     * The associated icon
     */
    icon: React.ReactNode;
};

const navbarItems = [
    {
        path: "/",
        key: "index",
        friendlyName: "Home",
        icon: <FontAwesomeIcon icon={["fas", "home"]} />,
    },
    {
        path: "/about",
        key: "about",
        friendlyName: "About",
        icon: <FontAwesomeIcon icon={["fas", "info-circle"]} />,
    },
    {
        path: "/login",
        key: "login",
        friendlyName: "Sign In",
        icon: <FontAwesomeIcon icon={["fas", "sign-in-alt"]} />,
    },
    {
        path: "/signup",
        key: "register",
        friendlyName: "Register",
        icon: <FontAwesomeIcon icon={["fas", "edit"]} />,
    }
] as INavbarItem[];

/**
 * This is a bootstrap navbar that is only active on the About page
 */
const AboutNavbar = () => {
    const navbarItemElems = navbarItems.map((item) => {
        let classNames = 'navbar-item';
        if (item.key === 'about') {
            classNames += ' active';
        }
        return <li className={classNames} key={item.key}>
            <a className="nav-link" href={item.path}>
                { item.icon }
                <span className="nav-text">{ item.friendlyName }</span>
            </a>
        </li>
    });

    return <Navbar className="navbar navbar-dark bg-primary fixed-top navbar-expand-lg" expand="md">
        <Container fluid>
            <Navbar.Brand className="navbar-brand" href="/">PassZero</Navbar.Brand>
            <Navbar.Toggle aria-controls="about-navbar-nav" />

            <Navbar.Collapse id="about-navbar-nav" role="navigation">
                <Nav className="navbar-nav ml-auto justify-content-end">
                    { navbarItemElems }
                </Nav>
            </Navbar.Collapse>
        </Container>
    </Navbar>;
};

const About = () => {
    return <>
        <AboutNavbar />
        <main className="container">
            <div className="inner-container">
                <div id="main-about-content" className="container">
                    <h2>About PassZero</h2>

                    <p>Remembering passwords is hard. That's why most people either use the same password for every site, or tend to use extremely insecure password. And how often do you forget your password? For me, it was all the time. That's why I wrote PassZero.</p>

                    <p>PassZero is a password manager: you can save the passwords for all your accounts on PassZero, and only need to remember one password. The passwords are securely encrypted with <b>your master password</b> so that they are completely secure, even if someone were to break into the PassZero servers.</p>

                    <div id="panel-container" className="row">
                        <div className="card col-sm">
                            <div className="card-body">
                                <h4 className="card-title">Strong Encryption</h4>
                                <div className="card-text">
                                    Your data is encrypted with <a href="https://en.wikipedia.org/wiki/Salsa20">Salsa20</a>, a powerful modern stream cipher that is also <a href="https://datatracker.ietf.org/doc/html/rfc9001">used in the new QUIC protocol</a>.
                                    The encryption key is derived from your private key, so only you have access to your data. Not even the PassZero team can decrypt it.
                                    Even in the unlikely event that hackers access our database, your data will still be secure.
                                </div>
                            </div>
                        </div>

                        <div className="card col-sm">
                            <div className="card-body">
                                <h4 className="card-title">Open Source</h4>
                                <div className="card-text">
                                    All the code for PassZero is available for anyone to view on <a href="https://github.com/boompig/passzero">GitHub</a>, so you can make sure we're as secure as we say we are. You can even see the code for this page! And if you want to make PassZero even better, make a pull request.
                                </div>
                            </div>
                        </div>

                        <div className="card col-sm">
                            <div className="card-body">
                                <h4 className="card-title">Multi-platform</h4>
                                <div className="card-text">Some password managers only work on some operating systems, or don't have mobile support. Not us! You can access PassZero from any (modern) browser, on any device. That means you can get all your passwords, whenever you need them.</div>
                            </div>
                        </div>
                    </div>

                    <a id="try-now-btn" className="btn btn-success" href="/signup">Try PassZero Today</a>

                    <div id="encryption-details">
                        <h2>Encryption Details</h2>
                        <p>PassZero encrypts each individual entry using the modern <a href="https://nacl.cr.yp.to/">NaCl cryptographic library</a>.
                            Each entry is encrypted with the XSalsa20 stream cipher and authenticated using a <a href="https://en.wikipedia.org/wiki/Poly1305">Poly1305 MAC</a> (thank you Daniel Bernstein).
                            Each entry is encrypted with its own key, derived from the master key using the <a href="https://en.wikipedia.org/wiki/Argon2">Argon2id KDF</a>.
                            Argon2id is a memory-hard key derivation function, which means it's both resistant to side-channel attacks and brute-force cost savings due to time-memory tradeoffs. For more details see the <a href="https://datatracker.ietf.org/doc/draft-irtf-cfrg-argon2/13/">IETF Draft</a>.</p>
                    </div>
                </div>
            </div>
        </main>
    </>;
};

export default About;