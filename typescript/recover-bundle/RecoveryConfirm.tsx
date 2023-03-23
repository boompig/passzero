import * as React from 'react';
import { useState, useEffect } from 'react';
import Alert from 'react-bootstrap/Alert';

import { pzApiv3 } from '../common-modules/passzero-api-v3';

export const RecoveryConfirm = () => {
    const url = new URL(window.location.href);
    const token = url.searchParams.get('token');
    if (!token) {
        throw new Error('token must be in URL params');
    }

    // email fetched from server
    const [email, setEmail] = useState('');
    const [password, setPassword] = useState('');
    const [confirmPassword, setConfirmPassword] = useState('');
    const [isConsentChecked, setConsentChecked] = useState(false);
    const [errorMsg, setErrorMsg] = useState('');
    const [successMsg, setSuccessMsg] = useState('');

    const handleSubmit = async (e: React.FormEvent) => {
        e.preventDefault();

        // reset
        setErrorMsg('');
        setSuccessMsg('');

        const r = await pzApiv3.recoverAccountConfirm(token, password, confirmPassword, isConsentChecked);
        if (r.ok) {
            console.log('recovered!');
            const j = await r.json();
            setSuccessMsg(j.msg);
        } else {
            console.error('account recovery failed');
            if(r.headers.get("Content-Type") === "application/json") {
                const j = await r.json();
                setErrorMsg(j.msg);
            } else {
                setErrorMsg('Recovery failed for some unknown reason.');
            }
        }
    };

    const handleCheck = (e: React.ChangeEvent<HTMLInputElement>) => {
        setConsentChecked(e.target.checked);
    };

    const handleChange = (e: React.ChangeEvent<HTMLInputElement>) => {
        if (e.target.name === 'password') {
            setPassword(e.target.value);
        } else {
            setConfirmPassword(e.target.value);
        }
    };

    const fetchEmailForToken = async () => {
        const r = await pzApiv3.recoveryGetEmailWithToken(token);
        if (r.ok) {
            const j = await r.json();
            console.log('ok');
            setEmail(j.user.email);
        } else {
            setErrorMsg('Failed to retrieve email with the provided token. You are probably using an expired token.');
        }
    };

    useEffect(() => {
        fetchEmailForToken();
    }, []);

    return <main id="recovery-confirm-main">
        <h2 className="title">Recover Your Account</h2>

        <div className="alert alert-warning"><strong>Warning</strong> Once completed, the recovery process will delete all your saved passwords, documents, and links.
        This is because your passwords are encrypted using your old password, so not even we can break this encryption.</div>

        <form role="form" onSubmit={handleSubmit} id="recover-form">
            { successMsg ? <Alert variant='success'>{ successMsg }</Alert> : null }
            { errorMsg ? <Alert variant='danger'>{ errorMsg }</Alert> : null }

            <fieldset>
                <label htmlFor="email">Email</label>
                <input type="email" className="form-control" name="email"
                    readOnly={true} placeholder="email" required={true}
                    value={email} autoComplete="off" />
            </fieldset>

            <fieldset>
                <label htmlFor="password">Password</label>
                <input type="password" name="password" className="form-control"
                    required={true} placeholder="password"
                    autoComplete='new-password'
                    onChange={handleChange} />
            </fieldset>

            <fieldset>
                <label htmlFor="confirm_password">Confirm Password</label>
                <input type="password" name="confirm_password" className="form-control"
                    required={true} placeholder="confirm password"
                    autoComplete='new-password'
                    onChange={handleChange} />
            </fieldset>

            <div className="form-check">
                <input type="checkbox" name="accept_risk" required={true} className="form-check-input"
                    onChange={handleCheck} />
                <label htmlFor="accept_risk" className='form-check-label'>I understand the risks</label>
            </div>
            <button type="submit" className="btn btn-primary form-control" disabled={!isConsentChecked}>
                Reset Password</button>
        </form>
    </main>;
};

export default RecoveryConfirm;