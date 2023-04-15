import * as React from 'react';
import { useState, useEffect, useContext } from 'react';

import { MasterPasswordContext } from '../providers/master-password-provider';
import { pzApiv3 } from '../common-modules/passzero-api-v3';
import { AccessTokenContext } from '../providers/access-token-provider';
import { clientSideLogout } from '../common-modules/client-side-utils';
import LogoutTimer from '../common-modules/logoutTimer';
import { LoggedInLayout } from '../components/LoggedInLayout';

// import "bootstrap/dist/css/bootstrap.min.css";
import '../common-css/advanced.css';

interface IEntryScore {
    id: number;
    account: string;
    score: number;
    feedback: string;
}

const getRowClass = (score: number): string => {
    if (score === 4) {
        return 'table-success';
    } else if (score === 3) {
        return 'table-warning';
    } else if (score < 3) {
        return 'table-danger';
    } else {
        throw new Error(`score ${score} is outside expectations`);
    }
};

export const PasswordStrengthMain = () => {
    const { masterPassword } = useContext(MasterPasswordContext);

    if (!masterPassword) {
        clientSideLogout();
        throw new Error('master password failed to load from context');
    }
    const accessToken = useContext(AccessTokenContext);
    if (!accessToken) {
        throw new Error('failed to fetch access token from context');
    }

    const logoutTimer = new LogoutTimer();
    const [entryScores, setEntryScores] = useState([] as IEntryScore[]);

    const fetchEntryScores = async (accessToken: string, numAttempts: number) => {
        if (accessToken && numAttempts < 2) {
            console.debug(`Getting password strength scores with token ${accessToken}...`);
            const r = await pzApiv3.getPasswordStrengthScores(accessToken, masterPassword);
            if (r.ok) {
                const j = await r.json();
                setEntryScores(j);
            } else {
                console.error('error - failed to fetch entry scores');
                console.error(r.status);
                const t = await r.text();
                console.error(t);
                if (r.status === 401) {
                    clientSideLogout();
                }
            }
        } else if (numAttempts >= 2) {
            throw new Error('stopping after 2 failures');
        } else {
            throw new Error('not fetching entry scores because access token not set');
        }
    };

    useEffect(() => {
        fetchEntryScores(accessToken, 0);
        if (!logoutTimer.isStarted) {
            logoutTimer.startLogoutTimer();
        }
    }, [accessToken]);

    const rows = entryScores.map((entry: IEntryScore) => {
        const rowClass = getRowClass(entry.score);
        return <tr className={rowClass} key={entry.id}>
            <td>
                <a href={'/entries/' + entry.id}>{entry.account}</a>
            </td>
            <td>{entry.score}</td>
            <td>{entry.feedback}</td>
        </tr>;
    });

    return <main>
        <h1 className="title">Password Strength</h1>
        <div>
            <table className="table table-striped table-bordered">
                <thead>
                    <tr>
                        <th>Account</th>
                        <th>Password Strength (0-4)</th>
                        <th>Recommendation</th>
                    </tr>
                </thead>
                <tbody>
                    {rows}
                </tbody>
            </table>
        </div>
    </main>;
};

export const PasswordStrength = () => {
    return <LoggedInLayout>
        <PasswordStrengthMain />
    </LoggedInLayout>;
};

export default PasswordStrength;
