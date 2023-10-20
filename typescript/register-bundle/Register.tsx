import { useState } from 'react';
import * as React from 'react';
import Alert from 'react-bootstrap/Alert';

import { pzApiv3 } from '../common-modules/passzero-api-v3';
import { LoggedOutNavbar } from '../components/LoggedOutNavbar';
import redirectFromHerokuToFly from '../common-modules/heroku-fly-migration';

// import "bootstrap/dist/css/bootstrap.min.css";
import '../common-css/landing.css';
import '../common-css/login.css';

/**
 * The expected token size
 * See config.py on the backend
 */
const EXPECTED_TOKEN_LENGTH = 32;

const RegisterForm = () => {
    const [email, setEmail] = useState('');
    const [password, setPassword] = useState('');
    const [confirmPassword, setConfirmPassword] = useState('');
    const [serverErrorMsg, setServerErrorMsg] = useState('');
    const [serverSuccessMsg, setServerSuccessMsg] = useState('');

    const handleTextChange = (e: React.ChangeEvent<HTMLInputElement>) => {
        const newValue = e.target.value;
        if (e.target.name === 'email') {
            setEmail(newValue);
        } else if (e.target.name === 'password') {
            setPassword(newValue);
        } else {
            setConfirmPassword(newValue);
        }
    };

    const handleSubmit = async (e: React.FormEvent) => {
        e.preventDefault();

        // hide everything
        setServerErrorMsg('');
        setServerSuccessMsg('');

        console.debug('registering...');

        try {
            const resp = await pzApiv3.registerUser(email, password, confirmPassword);
            setServerSuccessMsg(resp.msg);
        } catch (err: any) {
            console.error(err);
            if (err._type === 'ApiError' && (err.status === 401 || err.status === 400)) {
                setServerErrorMsg(err.message);
            } else {
                setServerErrorMsg('something went wrong');
            }
        }
    };

    return <div id="form-container">
        <form method="POST" onSubmit={handleSubmit} role="form" id="login-new-form">
            <h1 className="title">
                Sign Up for PassZero
            </h1>

            { serverErrorMsg ?
                <Alert variant='danger'>
                    <strong>Error!</strong>&nbsp;
                    <span className="error-text">{ serverErrorMsg }</span>
                </Alert> :
                null }

            { serverSuccessMsg ?
                <Alert variant='success'>
                    <strong>Hooray!</strong>&nbsp;
                    <span>{ serverSuccessMsg }</span>
                </Alert> :
                null }

            <input type="email" className="form-control" name="email" tabIndex={1}
                placeholder="email" required={true}
                autoComplete="email"
                onChange={handleTextChange} />

            <input type="password" className="form-control" name="password" tabIndex={2}
                placeholder="password" required={true}
                autoComplete="new-password"
                onChange={handleTextChange} />

            <input type="password" className="form-control" name="confirm_password" tabIndex={3}
                placeholder="confirm password" required={true}
                autoComplete="new-password"
                onChange={handleTextChange} />

            <button id="submit-btn" type="submit">Sign Up</button>
        </form>
    </div>;
};

const RegisterConfirmForm = () => {
    const url = new URL(window.location.href);
    const defaultToken = url.searchParams.get('token');
    if (!defaultToken) {
        console.error('token must be set');
        window.location.assign('/signup');
    }

    const [token, setToken] = useState(defaultToken);
    const [isWorking, setWorking] = useState(false);
    const [serverErrorMsg, setServerErrorMsg] = useState('');
    const [serverSuccessMsg, setServerSuccessMsg] = useState('');

    const handleChange = (e: React.ChangeEvent<HTMLInputElement>) => {
        setToken(e.target.value);
    };

    const handleSubmit = async (e?: React.SyntheticEvent) => {
        e?.preventDefault();

        if (token.length !== EXPECTED_TOKEN_LENGTH) {
            setServerErrorMsg(`The token must be exactly ${EXPECTED_TOKEN_LENGTH} characters long`);
            return;
        }

        setServerErrorMsg('');
        setServerSuccessMsg('');
        setWorking(true);

        try {
            const resp = await pzApiv3.registerUserConfirm(token);
            setServerSuccessMsg(resp.msg);
            // also redirect
            window.location.assign('/login?last_action=done_register');
        } catch (err: any) {
            console.error(err);
            if (err._type === 'ApiError') {
                setServerErrorMsg(err.message);
            }
        }

        setWorking(false);
    };

    React.useEffect(() => {
        /**
         * Triggered when the token has changed and it is the right length
         * Basically this is in response to a paste event
         */
        if (token && token.length === EXPECTED_TOKEN_LENGTH) {
            // submit the form
            handleSubmit();
        }
    }, [token]);

    return <div id="form-container">
        <form method="POST" onSubmit={handleSubmit} role='form' id='signup-confirm-form'>
            <h4 className='title'>Confirm Your Registration</h4>

            { serverErrorMsg ?
                <Alert variant='danger'>
                    <strong>Error!</strong>&nbsp;
                    <span className="error-text">{ serverErrorMsg }</span>
                </Alert> :
                null }

            { serverSuccessMsg ?
                <Alert variant='success'>
                    <strong>Hooray!</strong>&nbsp;
                    <span>{ serverSuccessMsg }</span>
                </Alert> :
                null }

            <input type="text" className='form-control' name='token' tabIndex={3}
                placeholder='Paste your token from your email here'
                required disabled={isWorking}
                value={token}
                minLength={EXPECTED_TOKEN_LENGTH}
                maxLength={EXPECTED_TOKEN_LENGTH}
                onChange={handleChange} />
            <button type='submit' id='submit-btn' disabled={isWorking}>Confirm</button>
        </form>
    </div>;
};

export const Register = () => {
    const path = window.location.pathname;
    redirectFromHerokuToFly();

    return <div id="new-login">
        <div id="hero">
            <LoggedOutNavbar />
            { path === '/signup/confirm' ?
                <RegisterConfirmForm /> :
                <RegisterForm /> }
        </div>
    </div>;
};

export default Register;
