import * as React from 'react';

import AboutNavbar from '../components/AboutNavbar';

import './about.css';

const AboutMain = () => {
    return <main className="container">
        <div className="inner-container">
            <div id="main-about-content" className="container">
                <h2>About PassZero</h2>

                <p>Remembering passwords is hard.
                    That&apos;s why most people either use the same password for every site, or tend to use extremely insecure password.
                    And how often do you forget your password? For me, it was all the time.
                    That&apos;s why I wrote PassZero.</p>

                <p>PassZero is a password manager: you can save the passwords for all your accounts on PassZero, and only need to remember one password.
                    The passwords are securely encrypted with <b>your master password</b> so that they are completely secure, even if someone were to break into the PassZero servers.</p>

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
                                All the code for PassZero is available for anyone to view on <a href="https://github.com/boompig/passzero">GitHub</a>, so you can make sure we&apos;re as secure as we say we are.
                                You can even see the code for this page! And if you want to make PassZero even better, make a pull request.
                            </div>
                        </div>
                    </div>

                    <div className="card col-sm">
                        <div className="card-body">
                            <h4 className="card-title">Multi-platform</h4>
                            <div className="card-text">Some password managers only work on some operating systems, or don&apos;t have mobile support. Not us! You can access PassZero from any (modern) browser, on any device. That means you can get all your passwords, whenever you need them.</div>
                        </div>
                    </div>
                </div>

                <a id="try-now-btn" className="btn btn-success" href="/signup">Try PassZero Today</a>

                <div id="encryption-details">
                    <h2>Encryption Details</h2>
                    <p>PassZero encrypts each individual entry using the modern <a href="https://nacl.cr.yp.to/">NaCl cryptographic library</a>.
                        Each entry is encrypted with the XSalsa20 stream cipher and authenticated using a <a href="https://en.wikipedia.org/wiki/Poly1305">Poly1305 MAC</a> (thank you Daniel Bernstein).
                        Each entry is encrypted with its own key, derived from the master key using the <a href="https://en.wikipedia.org/wiki/Argon2">Argon2id KDF</a>.
                        Argon2id is a memory-hard key derivation function, which means it&apos;s both resistant to side-channel attacks and brute-force cost savings due to time-memory tradeoffs.
                        For more details see the <a href="https://datatracker.ietf.org/doc/draft-irtf-cfrg-argon2/13/">IETF Draft</a>.</p>
                </div>
            </div>
        </div>
    </main>;
};

export const About = () => {
    return <>
        <header>
            <AboutNavbar />
        </header>
        <AboutMain />
    </>;
};

export default About;
