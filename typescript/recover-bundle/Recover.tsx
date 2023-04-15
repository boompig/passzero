import * as React from 'react';

import { RecoveryStart } from './RecoveryStart';
import { RecoveryConfirm } from './RecoveryConfirm';
import AboutNavbar from '../components/AboutNavbar';

// import "bootstrap/dist/css/bootstrap.min.css";
import './recover.css';

export const RecoverMain = () => {
    // figure out if we're in step 1 or 2 of the recovery flow
    const u = new URL(window.location.href);
    const recoveryToken = u.searchParams.get('token');
    if (recoveryToken) {
        return <RecoveryConfirm />;
    } else {
        return <RecoveryStart />;
    }
};

const Recover = () => {
    return <div className='container'>
        <header>
            <AboutNavbar />
        </header>
        <RecoverMain />
    </div>;
};

export default Recover;
