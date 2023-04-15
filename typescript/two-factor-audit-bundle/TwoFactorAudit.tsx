import * as React from 'react';
import { useState, useEffect, useContext } from 'react';

import { pzApiv3 } from '../common-modules/passzero-api-v3';
import { AccessTokenContext } from '../providers/access-token-provider';
import LogoutTimer from '../common-modules/logoutTimer';
import { clientSideLogout } from '../common-modules/client-side-utils';
import { LoggedInLayout } from '../components/LoggedInLayout';

// import "bootstrap/dist/css/bootstrap.min.css";
import '../common-css/advanced.css';

interface ITwoFactorMapEntry {
    // eslint-disable-next-line
    service_has_2fa: boolean;
    // eslint-disable-next-line
    entry_has_2fa: boolean;
    // eslint-disable-next-line
    entry_id: number;
}

const getRowClass = (entry: ITwoFactorMapEntry): string => {
    if (entry.service_has_2fa && entry.entry_has_2fa) {
        return 'table-success';
    } else if (entry.service_has_2fa && !entry.entry_has_2fa) {
        return 'table-danger';
    } else {
        return '';
    }
};

type TwoFactorMapResponse = {[key: string]: ITwoFactorMapEntry};

const TwoFactorAuditMain = () => {
    const accessToken = useContext(AccessTokenContext);
    if (!accessToken) {
        throw new Error('failed to load access token from context');
    }

    const logoutTimer = new LogoutTimer();
    const [twoFactorMap, setTwoFactorMap] = useState({} as TwoFactorMapResponse);

    const rows = Object.entries(twoFactorMap).map(([account, entry]) => {
        const rowClass = getRowClass(entry);
        return <tr className={rowClass} key={entry.entry_id}>
            <td>{ account } <a href={'/edit/' + entry.entry_id}>edit</a></td>
            <td>{ entry.service_has_2fa ? entry.service_has_2fa.toString() : '?' }</td>
            <td>{ entry.entry_has_2fa ? entry.entry_has_2fa.toString() : '?' }</td>
        </tr>;
    });

    const fetchTwoFactorMap = async () => {
        const r = await pzApiv3.getTwoFactorAudit(accessToken);
        if (r.ok) {
            const resp = (await r.json()) as TwoFactorMapResponse;
            setTwoFactorMap(resp);
        } else {
            console.error('failed to fetch two factor map');
            if (r.status === 401) {
                // likely the token has expired
                clientSideLogout();
            } else {
                throw new Error('failed to fetch two factor map');
            }
        }
    };

    useEffect(() => {
        fetchTwoFactorMap();
        if (!logoutTimer.isStarted) {
            logoutTimer.startLogoutTimer();
        }
    }, []);

    return <main>
        <h1 className="title">2Factor Audit</h1>
        <div>
            <table id="2fa-audit-table" className="table table-striped table-bordered">
                <thead>
                    <tr>
                        <th>Account</th>
                        <th>Possible to enable 2FA on this service</th>
                        <th>Has 2FA enabled</th>
                    </tr>
                </thead>
                <tbody>
                    {rows}
                </tbody>
            </table>
        </div>
    </main>;
};

export const TwoFactorAudit = () => {
    return <LoggedInLayout>
        <TwoFactorAuditMain />
    </LoggedInLayout>;
};

export default TwoFactorAudit;
