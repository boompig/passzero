import * as React from 'react';
import { useState } from 'react';
import Alert from 'react-bootstrap/Alert';

import { pzApiv3 } from '../common-modules/passzero-api-v3';

export const RecoveryStart = () => {
    const [email, setEmail] = useState('');
    const [isConsentChecked, setConsentChecked] = useState(false);
    const [errorMsg, setErrorMsg] = useState('');
    const [successMsg, setSuccessMsg] = useState('');

    const handleCheck = (e: React.ChangeEvent<HTMLInputElement>) => {
        setConsentChecked(e.target.checked);
    };

    const handleChange = (e: React.ChangeEvent<HTMLInputElement>) => {
        setEmail(e.target.value);
    };

    const handleSubmit = async (e: React.FormEvent) => {
        e.preventDefault();

        setErrorMsg('');
        setSuccessMsg('');

        // success case
        const r = await pzApiv3.recoverAccountStart(email, isConsentChecked);
        if (r.ok) {
            const j = await r.json();
            setSuccessMsg(j.msg);
        } else {
            console.error(r);
            if (r.headers.get('Content-Type') === 'application/json') {
                const j = await r.json();
                setErrorMsg(j.msg);
            } else {
                setErrorMsg('something went wrong');
            }
        }
    };

    return <main id="recovery-start-main">
        <h2 className="title">Recover Password</h2>

        <div className="alert alert-warning"><strong>Warning</strong> Once completed, the recovery process will delete all your saved passwords, links, and user profile data.
        This is because your passwords are encrypted using your old password, so not even we can break this encryption.</div>

        <form role="form" onSubmit={handleSubmit} id="recover-form">
            { successMsg ? <Alert variant='success'>{ successMsg }</Alert> : null }
            { errorMsg ? <Alert variant='danger'>{ errorMsg }</Alert> : null }

            <fieldset>
                <label htmlFor="email">Email</label>
                <input type="email" className="form-control" name="email"
                    required={true} placeholder="email"
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
