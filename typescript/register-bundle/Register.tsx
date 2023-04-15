import { useState } from 'react';
import * as React from 'react';

import { pzApiv3 } from '../common-modules/passzero-api-v3';
import { LoggedOutNavbar } from '../components/LoggedOutNavbar';

// import "bootstrap/dist/css/bootstrap.min.css";
import '../common-css/landing.css';
import '../common-css/login.css';

const getMessageFromErrorCode = (errorCode: string): string => {
    if (!errorCode) {
        throw new Error('error code not specified');
    }
    switch (errorCode) {
        case 'err_register_token_expired':
            return 'The token has expired.';
        case 'err_register_token_invalid':
            return 'The provided token is invalid.';
        default:
            throw new Error(`invalid error code: ${errorCode}`);
    }
};

const RegisterForm = () => {
    const url = new URL(window.location.href);
    // initial value
    const serverErrorCode = url.searchParams.get('error_code');

    const [email, setEmail] = useState('');
    const [password, setPassword] = useState('');
    const [confirmPassword, setConfirmPassword] = useState('');
    const [serverErrorMsg, setServerErrorMsg] = useState(serverErrorCode ? getMessageFromErrorCode(serverErrorCode) : '');
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
                <div className="alert alert-danger">
                    <strong>Error!</strong>&nbsp;
                    <span className="error-text">{ serverErrorMsg }</span>
                </div> :
                null }

            { serverSuccessMsg ?
                <div className="alert alert-success">
                    <strong>Hooray!</strong>&nbsp;
                    <span>{ serverSuccessMsg }</span>
                </div> :
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

export const Register = () => {
    return <div id="new-login">
        <div id="hero">
            <LoggedOutNavbar />
            <RegisterForm />
        </div>
    </div>;
};

export default Register;
