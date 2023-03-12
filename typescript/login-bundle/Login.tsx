import { useState, useEffect } from "react";
import * as React from "react";

import { pzApiv3 } from "../common-modules/passzero-api-v3";
import { LoggedOutNavbar } from "../components/LoggedOutNavbar";
import { saveMasterPassword } from "../providers/master-password-provider";
import { saveAccessToken } from "../providers/access-token-provider";

// import "bootstrap/dist/css/bootstrap.min.css";
// import "./login.css";

const EntriesRedirect = () => {
    return <div>
        <h1>You are logged in</h1>
        <p>Redirecting to entries. <a href="/entries">Click here</a> if it's taking too long...</p>
    </div>;
};

const LoginForm = () => {
    const [usernameOrEmail, setUsernameOrEmail] = useState('');
    const [password, setPassword] = useState('');
    const [isChecked, setChecked] = useState(false);
    const [isShowSlowWarning, setShowSlowWarning] = useState(false);
    const [errorMsg, setErrorMsg] = useState('');

    const handleTextChange = (e: React.ChangeEvent<HTMLInputElement>) => {
        const newValue = e.target.value;
        if (e.target.name === 'password') {
            setPassword(newValue);
        } else {
            setUsernameOrEmail(newValue);
            if (isChecked && newValue) {
                // update the saved email
                localStorage.setItem('username_or_email', newValue);
                console.debug('saved');
            }
        }
    };

    const handleCheckboxChange = (e: React.ChangeEvent<HTMLInputElement>) => {
        setChecked(e.target.checked);
        if (e.target.checked && usernameOrEmail) {
            // update the saved email
            localStorage.setItem('username_or_email', usernameOrEmail);
            console.debug('saved');
        }
    };

    // const triggerSlowWarning = () => {
    //     if (!isLoggedIn && !errorMsg) {
    //         console.debug('showing slow warning');
    //         console.debug(errorMsg);
    //         console.debug(isLoggedIn);
    //         setShowSlowWarning(true);
    //     }
    // };

    const handleSubmit = async (e: React.FormEvent<HTMLFormElement>) => {
        e.preventDefault();

        console.debug('logging in...');

        // reset everything
        setShowSlowWarning(false);
        // setLoggedIn(false);
        setErrorMsg('');

        // we have a slow warning...
        console.debug('setting slow detection timeout...')
        // window.setTimeout(triggerSlowWarning, 1000);

        try {
            const resp = await pzApiv3.login(usernameOrEmail, password);
            console.debug('logged in!');
            // setLoggedIn(true);
            setShowSlowWarning(false);

            // save the master password
            console.debug('saving master password to context...');
            saveMasterPassword(password);

            console.debug('saving access token to context...');
            saveAccessToken(resp.token);

            // redirect over to entries
            console.debug(`redirecting to entries...`);
            window.location.assign('/entries');
            return <EntriesRedirect />;
        } catch (err: any) {
            console.error(err);
            if (err._type === 'ApiError' && err.status === 401) {
                console.debug('unauthorized!');
                setErrorMsg(err.message);
                console.debug(err.message);
                setShowSlowWarning(false);
            } else {
                console.error('failed to login');
            }
        }

        return false;
    };

    const getRemember = () => {
        const _u = localStorage.getItem('username_or_email');
        console.debug(`Read saved value: ${_u}`);
        if (_u) {
            setUsernameOrEmail(_u);
            setChecked(true);
        }
    };

    useEffect(() => {
        getRemember();
    }, []);

    return <div id="form-container">
        <form method="POST" id="login-existing-form" role="form"
            onSubmit={handleSubmit}>
            <h1 className="title">
                Login to PassZero
            </h1>

            { errorMsg ?
                <div className="alert alert-danger" id="error-msg-container" role="alert">
                    <div id="error-msg">{ errorMsg }</div>
                </div> :
                null }

            { isShowSlowWarning ?
                <div className="alert alert-warning" id="progress-alert" role="alert">
                    <span>This is taking longer than usual...</span>
                </div> :
                null }

            <div className="form-group">
                <input type="text" className="form-control" name="username_or_email" tabIndex={1}
                        placeholder="username or email" required={true} autoComplete="username"
                        value={usernameOrEmail}
                        onChange={handleTextChange} />
            </div>

            <div className="form-group">
                <input type="password" className="form-control" name="password" tabIndex={2}
                    autoComplete="current-password"
                    placeholder="password" required={true}
                    value={password}
                    onChange={handleTextChange} />
            </div>

            <div className="form-check">
                <input type="checkbox" name="remember" tabIndex={3}
                    className="form-check-input"
                    checked={isChecked}
                    onChange={handleCheckboxChange} />
                <label htmlFor="remember" className="form-check-label">Remember me</label>
            </div>

            {/* TODO */}
            {/* <a id="forgot-password" href="{{ url_for("main_routes.recover_password") }}">Forgot Password</a> */}

            <a id="forgot-password" href="/recover">Forgot Password</a>

            <button id="submit-btn" type="submit" name="submit">Log In</button>
        </form>
    </div>;
};

export const Login = () => {
    return <div id="existing-login">
        <div id="hero">
            <LoggedOutNavbar />
            {/* TODO */}
            {/* {% include "flash_messages.jinja2" %} */}
            <LoginForm />
        </div>
    </div>;
};

export default Login;