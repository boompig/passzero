import * as React from 'react';
import { useState, useContext } from 'react';
import Tab from 'react-bootstrap/Tab';
import Tabs from 'react-bootstrap/Tabs';
import Alert from 'react-bootstrap/Alert';

import { pzApiv3 } from '../common-modules/passzero-api-v3';
import { MasterPasswordContext } from '../providers/master-password-provider';
import { AccessTokenContext } from '../providers/access-token-provider';
import { clientSideLogout } from '../common-modules/client-side-utils';
import { AccessTokenProvider } from '../components/AccessTokenProvider';

// import "bootstrap/dist/css/bootstrap.min.css";
import './advanced.css';

const NukePane = () => {
    const accessToken = useContext(AccessTokenContext);
    if (!accessToken) {
        throw new Error('failed to load access token from context');
    }
    const { masterPassword } = useContext(MasterPasswordContext);
    if (!masterPassword) {
        throw new Error('failed to load master password from context');
    }

    const [successMsg, setSuccessMsg] = useState('');
    const [errorMsg, setErrorMsg] = useState('');

    const handleSubmit = async (e: React.SyntheticEvent) => {
        e.preventDefault();
        setSuccessMsg('');
        setErrorMsg('');

        if (confirm('Are you sure you want to delete all your entries?')) {
            try {
                const resp = await pzApiv3.deleteAllEntries(accessToken, masterPassword);
                console.debug('all entries have been deleted');
                // note that if we have not thrown an error then it's a success
                setSuccessMsg(resp.msg);
            } catch (err: any) {
                console.error(err);
                if (err._type === 'ApiError' && err.status === 401) {
                    // token has likely expired
                    clientSideLogout();
                } else if (err._type === 'ApiError' && err.message) {
                    setErrorMsg(err.message);
                } else {
                    setErrorMsg('something went wrong');
                }
            }
        }
        return false;
    };

    return <div id="nuke-container">
        <div className="alert alert-warning"><strong>Warning</strong> This action deletes all your entries and cannot be undone</div>

        { successMsg ?
            <Alert variant="success" id="nuke-success-msg">{ successMsg }</Alert> :
            null }

        { errorMsg ?
            <Alert variant='danger'>{ errorMsg }</Alert> :
            null }

        <form role="form" method="POST" id="nuke-entries-form"
            onSubmit={handleSubmit}>
            <button type="submit" className="btn btn-danger">Nuke Entries</button>
        </form>
    </div>;
};

const UpdateEntryVersionsPane = () => {
    const accessToken = useContext(AccessTokenContext);
    if (!accessToken) {
        throw new Error('failed to load access token from context');
    }
    const { masterPassword } = useContext(MasterPasswordContext);
    if (!masterPassword) {
        throw new Error('failed to load master password from context');
    }

    const [successMsg, setSuccessMsg] = useState('');
    const [errorMsg, setErrorMsg] = useState('');

    const handleSubmit = async (e: React.SyntheticEvent) => {
        e.preventDefault();
        setSuccessMsg('');
        setErrorMsg('');
        try {
            console.debug('Updating entry versions...');
            const resp = await pzApiv3.updateEntryVersions(accessToken, masterPassword);
            setSuccessMsg(`Done. Updated ${resp.num_updated} entries.`);
        } catch (err: any) {
            console.error(err);
            if (err._type === 'ApiError' && err.status === 401) {
                // token has likely expired
                clientSideLogout();
            } else if (err._type === 'ApiError' && err.message) {
                setErrorMsg(err.message);
            } else {
                setErrorMsg('something went wrong');
            }
        }
    };

    return <div id="update-entry-versions-container">
        <p>Update all your entries to the newest version to increase security and gain access to new features.</p>

        { successMsg ?
            <Alert variant="success">{ successMsg }</Alert>:
            null }

        { errorMsg ?
            <Alert variant="danger">{ errorMsg }</Alert>:
            null }

        <form role="form" onSubmit={handleSubmit}>
            <button className="btn btn-success" type='submit'>Update Entry Versions</button>
        </form>
    </div>;
};

export const AdvancedMain = () => {
    return <div id="advanced-main">
        <h1 className="title">Advanced Options</h1>

        <div id="advanced-tabpanel">
            <Tabs id="advanced-tabpanel" defaultActiveKey="export">
                <Tab id="password-strength" className="password-strength-pane" eventKey="password-strength" title="Password Strength">
                    <div id="password-strength-container" className="tab-text-container">
                        <p><a href="/entries/strength">Click here</a> to see password strength for all your entries</p>
                    </div>
                </Tab>
                <Tab id="mfa-audit" className="mfa-audit-pane" eventKey="mfa-audit" title="MFA Audit">
                    <div id="2fa-audit-container" className="tab-text-container">
                        <p><a href="/entries/2fa">Click here</a> to see whether 2FA is enabled for all your entries</p>
                    </div>
                </Tab>
                <Tab id="export" className="export-pane" eventKey="export" title="Export">
                    <div id="export-container" className="tab-text-container">
                        <p>Generate a CSV file of all your entries, still encrypted. Read about how your data is encrypted so you can decrypt it locally.</p>

                        <a id="export-btn" className="btn btn-success"
                            href="/advanced/export">Export Entries</a>
                    </div>
                </Tab>
                <Tab id="nuke" className="nuke-pane" eventKey="nuke" title="Nuke">
                    <NukePane />
                </Tab>
                <Tab id="update-entry-versions" className="update-entry-versions-pane" eventKey="update-entry-versions" title="Update Entry Versions">
                    <UpdateEntryVersionsPane />
                </Tab>
            </Tabs>
        </div>
    </div>;
};

export const Advanced = () => {
    return <AccessTokenProvider>
        <AdvancedMain />
    </AccessTokenProvider>;
};

export default Advanced;
