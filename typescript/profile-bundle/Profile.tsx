import * as React from 'react';
import { useState, useEffect } from 'react';
import Alert from 'react-bootstrap/Alert';

import PasszeroApiV3, { IUser } from '../common-modules/passzero-api-v3';
import LogoutTimer from '../common-modules/logoutTimer';
import { LoggedInLayout } from '../components/LoggedInLayout';
import { clientSideLogout } from '../common-modules/client-side-utils';

import '../common-css/advanced.css';
import './profile.css';

const UserPrefs = ({ user, onUpdate }: { user: IUser, onUpdate(): void }) => {
    const pzApi = new PasszeroApiV3();

    // state
    const [numPasswordChars, setNumPasswordChars] = useState(user.preferences.default_random_password_length);
    const [numPassphraseChars, setNumPassphraseChars] = useState(user.preferences.default_random_passphrase_length);
    const [successMsg, setSuccessMsg] = useState('');

    const handleChangeNumber = (e: React.ChangeEvent<HTMLInputElement>) => {
        const v = Number.parseInt(e.target.value);
        if (v) {
            if (e.target.name === 'default_random_password_length') {
                setNumPasswordChars(v);
            } else if (e.target.name === 'default_random_passphrase_length') {
                setNumPassphraseChars(v);
            }
        }
    };

    const handleSubmit = async (e: React.FormEvent) => {
        e.preventDefault();
        setSuccessMsg('');
        console.debug('updating current user preferences');
        const resp = await pzApi.updateCurrentUser({
            preferences: {
                default_random_password_length: numPasswordChars,
                default_random_passphrase_length: numPassphraseChars,
            },
        });
        console.debug(resp);
        // setSuccessMsg(resp.msg);
        setSuccessMsg('successfully updated user preferences');
        onUpdate();
    };

    return <div id="user-prefs-container">
        <h3 className="title">Random password generation preferences</h3>
        <form role="form" id="user-prefs-form" onSubmit={handleSubmit}>
            { successMsg ? <Alert variant="success">{ successMsg }</Alert> : null }

            <label>Default number of characters in random password</label>
            <input type="number" name="default_random_password_length"
                className="form-control"
                defaultValue={ user.preferences.default_random_password_length }
                onChange={handleChangeNumber}
                min={1} max={255} />
            <label>Default number of words in random passphrase</label>
            <input type="number" name="default_random_passphrase_length"
                className="form-control"
                defaultValue={ user.preferences.default_random_passphrase_length }
                onChange={handleChangeNumber}
                min={1} max={10} />
            <button type="submit" className="btn btn-success form-control">Save</button>
        </form>
    </div>;
};

const ChangeUsernameForm = ({ onUpdate }: { onUpdate(): void }) => {
    const pzApi = new PasszeroApiV3();
    const [username, setUsername] = useState('');
    const [successMsg, setSuccessMsg] = useState('');
    const [errorMsg, setErrorMsg] = useState('');

    const handleSubmit = async (e: React.SyntheticEvent) => {
        e.preventDefault();
        setSuccessMsg('');
        setErrorMsg('');

        try {
            await pzApi.updateCurrentUser({
                username: username,
            });
            setSuccessMsg('Updated username successfully');
            onUpdate();
        } catch (err: any) {
            console.error(err);
            setErrorMsg(err.message);
        }
    };

    const handleChange = (e: React.ChangeEvent<HTMLInputElement>) => {
        setUsername(e.target.value);
    };

    return <form role="form" id="changeUsernameForm" onSubmit={handleSubmit}>
        {successMsg ? <Alert variant="success">{successMsg}</Alert> : null}
        {errorMsg ? <Alert variant="danger">{errorMsg}</Alert> : null}

        <div className="form-group">
            <div className="row">
                <label htmlFor="username" className="col-sm-2 col-form-label">username</label>
                <div className="col-sm-7">
                    <input type="text" name="username" className="form-control" placeholder="your unique username"
                        required={true} minLength={2} maxLength={16}
                        autoComplete="off"
                        onChange={handleChange} />
                </div>
            </div>
            <div className="row">
            </div>
        </div>
        <button type="submit" className="form-control btn-success">save username</button>
    </form>;
};

const UserProfile = ({ user, onUpdate }: {user: IUser, onUpdate(): void }) => {
    const [isShowForm, setShowForm] = useState(false);

    return <div>
        <h3 className="title">User Profile</h3>
        <table className="table table-sm table-borderless" id="readonly-user-details">
            <tbody>
                <tr>
                    <td className="table-info-cell">email</td><td>{ user.email }</td>
                </tr>
                <tr>
                    <td className="table-info-cell">last login</td><td>{ user.last_login }</td>
                </tr>
                <tr>
                    <td className="table-info-cell">username</td><td>{ user.username }</td>
                </tr>
            </tbody>
        </table>

        { isShowForm ? null : <button className="btn btn-info"
            onClick={() => setShowForm(true)}>change username</button>}

        { isShowForm ? <ChangeUsernameForm onUpdate={onUpdate} /> : null }
    </div>;
};

const ChangePassword = ({ user, onUpdate }: { user: IUser, onUpdate(): void}) => {
    const pzApi = new PasszeroApiV3();
    const [oldPassword, setOldPassword] = useState('');
    const [newPassword, setNewPassword] = useState('');
    const [confirmNewPassword, setConfirmNewPassword] = useState('');
    const [successMsg, setSuccessMsg] = useState('');
    const [errorMsg, setErrorMsg] = useState('');
    const [isWorking, setWorking] = useState(false);

    const handleChange = (e: React.ChangeEvent<HTMLInputElement>) => {
        const name = e.target.name;
        const value = e.target.value;
        if (name === 'old_password') {
            setOldPassword(value);
        } else if (name === 'new_password') {
            setNewPassword(value);
        } else {
            setConfirmNewPassword(value);
        }
    };

    const handleSubmit = async (e: React.SyntheticEvent) => {
        e.preventDefault();
        setSuccessMsg('');
        setErrorMsg('');

        if (newPassword !== confirmNewPassword) {
            setErrorMsg('Passwords do not match');
            return;
        }
        if (oldPassword === newPassword) {
            setErrorMsg('Old password and new password are the same');
            return;
        }

        setWorking(true);
        const r = await pzApi.changePassword(
            oldPassword,
            newPassword,
            confirmNewPassword,
        );
        if (r.ok) {
            setSuccessMsg('Successfully changed password');
            setWorking(false);
        } else {
            const j = await r.json();
            setErrorMsg(j.msg);
            setWorking(false);
        }
    };

    return <>
        <div className="progress-alert alert alert-info" role="alert"></div>
        <div id="change-password-container">
            <h3 className="title">Change Account Password</h3>
            <form role="form" id="change-password-form" onSubmit={handleSubmit}>
                {successMsg ? <Alert variant="success">{successMsg}</Alert> : null}
                {errorMsg ? <Alert variant="danger">{errorMsg}</Alert> : null}

                <div>
                    <div className="error-msg"></div>
                    <label htmlFor="old_password">Old Password</label>
                </div>

                <div>
                    <span className="form-error" id="form-error-old_password"></span>
                    <input type="password" name="old_password" className="form-control"
                        placeholder="old password" required={true}
                        autoComplete="off"
                        onChange={handleChange} />
                </div>

                <div>
                    <label htmlFor="new_password">New Password</label>
                    <input type="password" name="new_password" className="form-control"
                        placeholder="new password" required={true}
                        autoComplete="off"
                        onChange={handleChange} />
                </div>

                <div>
                    <label htmlFor="confirm_new_password">Confirm New Password</label>
                    <input type="password" name="confirm_new_password" className="form-control"
                        placeholder="confirm new password" required={true}
                        autoComplete="off"
                        onChange={handleChange} />
                </div>

                <button type="submit" className="btn btn-success form-control"
                    id="change-password-btn"
                    disabled={isWorking}>Change Password</button>
            </form>
        </div>
    </>;
};

const DeleteAccount = () => {
    const pzApi = new PasszeroApiV3();
    const [password, setPassword] = useState('');
    const [successMsg, setSuccessMsg] = useState('');
    const [errorMsg, setErrorMsg] = useState('');
    const [isWorking, setWorking] = useState(false);

    const handleChange = (e: React.ChangeEvent<HTMLInputElement>) => {
        setPassword(e.target.value);
    };

    const handleSubmit = async (e: React.SyntheticEvent) => {
        e.preventDefault();

        if (isWorking) {
            return;
        }

        setWorking(true);
        setErrorMsg('');
        setSuccessMsg('');

        const r = await pzApi.deleteAccount(password);
        setWorking(false);
        if (r.ok) {
            setSuccessMsg('Successfully deleted the account');
            clientSideLogout();
        } else {
            const j = await r.json();
            console.error(j);
            setErrorMsg(j.msg);
        }
    };

    return <>
        <h3 className="title">Delete Account</h3>
        <div className="alert alert-danger" role="alert">
            <strong>Warning!</strong> This action cannot be undone.
        </div>
        <form role="form" id="delete-user-form" onSubmit={handleSubmit}>
            {successMsg ? <Alert variant="success">{successMsg}</Alert> : null}
            {errorMsg ? <Alert variant="danger">{errorMsg}</Alert> : null}

            <p>Type your master password to proceed</p>
            <input type="password" name="password" className="form-control" required={true}
                placeholder="master password"
                autoComplete="off"
                onChange={handleChange} />
            <button type="submit" className="btn btn-danger form-control"
                disabled={isWorking}>Delete my account forever</button>
        </form>
    </>;
};

const ProfileInner = () => {
    let logoutTimer = null as LogoutTimer | null;
    const api = new PasszeroApiV3();

    // state
    const [user, setUser] = useState(null as IUser | null);

    const resetTimer = () => {
        if (logoutTimer) {
            logoutTimer.resetLogoutTimer();
        }
    };

    const fetchUser = async () => {
        const user = await api.getCurrentUser();
        console.log(user);
        setUser(user);
    };

    useEffect(() => {
        fetchUser();

        // start the logout timer
        logoutTimer = new LogoutTimer();
        logoutTimer.startLogoutTimer();
    }, []);

    return (<div id="profile-app" onClick={resetTimer} onScroll={resetTimer}>
        <h1 className="title">Profile</h1>

        <div id="global-error-msg" className="alert alert-danger" role="alert">
            <strong>Error</strong>
            <span className="text"></span>
        </div>
        <div id="global-success-msg" className="alert alert-success" role="alert"></div>

        <div id="advanced-tabpanel" role="tabpanel">
            <ul className="nav nav-tabs" role="tablist">
                <li className="nav-item" role="presentation">
                    <a className="nav-link active" href="#user-profile" aria-controls="user-profile" role="tab" data-toggle="tab" aria-selected="true">Profile</a>
                </li>
                <li className="nav-item" role="presentation">
                    <a className="nav-link" href="#change-password" aria-controls="change-password" role="tab" data-toggle="tab" aria-selected="false">Change Account Password</a>
                </li>
                <li className="nav-item" role="presentation">
                    <a className="nav-link" href="#delete-user" aria-controls="delete-user" role="tab" data-toggle="tab" aria-selected="false">Delete Account</a>
                </li>
            </ul>
            <div className="tab-content" id="profile-tab-content">
                <div id="user-profile" className="tab-pane active" role="tabpanel">
                    { user ? <UserProfile user={user} onUpdate={fetchUser} /> : null }
                    { user ? <UserPrefs user={user} onUpdate={fetchUser} />: null }
                </div>
                <div id="delete-user" className="tab-pane" role="tabpanel">
                    { user ? <DeleteAccount /> : null }
                </div>
                <div id="change-password" className="tab-pane" role="presentation">
                    { user ? <ChangePassword user={user} onUpdate={fetchUser} /> : null }
                </div>
            </div>
        </div>
    </div>);
};

const Profile = () => {
    return <LoggedInLayout>
        <ProfileInner />
    </LoggedInLayout>;
};

export default Profile;
