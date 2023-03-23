import * as React from 'react';
import { useState, useEffect, useContext } from 'react';

import { pzApiv3 } from '../common-modules/passzero-api-v3';
import { AccessTokenProvider } from '../components/AccessTokenProvider';
import { AccessTokenContext } from '../providers/access-token-provider';
// import { clientSideLogout } from '../common-modules/client-side-utils';

// instead of importing include it using a reference (since it's not a module)
// similarly for LogoutTimer variable
// / <reference path="../common/logoutTimer.ts" />

interface ITwoFactorMapEntry {
    service_has_2fa: boolean;
    entry_has_2fa: boolean;
    entry_id: number;
}

const getRowClass = (entry: ITwoFactorMapEntry): string => {
    if (entry.service_has_2fa && entry.entry_has_2fa) {
        return "table-success";
    } else if (entry.service_has_2fa && !entry.entry_has_2fa) {
        return "table-danger";
    } else {
        return "";
    }
};

type TwoFactorMapResponse = {[key: string]: ITwoFactorMapEntry};

const TwoFactorAuditMain = () => {
    const accessToken = useContext(AccessTokenContext);
    const [twoFactorMap, setTwoFactorMap] = useState({} as TwoFactorMapResponse);

    const rows = Object.entries(twoFactorMap).map(([account, entry]) => {
        const rowClass = getRowClass(entry);
        return <tr className={rowClass} key={entry.entry_id}>
            <td>{ account } <a href={"/edit/" + entry.entry_id}>edit</a></td>
            <td>{ entry.service_has_2fa ? entry.service_has_2fa.toString() : "?" }</td>
            <td>{ entry.entry_has_2fa ? entry.entry_has_2fa.toString() : "?" }</td>
        </tr>
    });

    const fetchTwoFactorMap = async () => {
        const r = await pzApiv3.getTwoFactorAudit(accessToken);
        if (r.ok) {
            const resp = (await r.json()) as TwoFactorMapResponse;
            setTwoFactorMap(resp);
        } else {
            console.error('failed to fetch two factor map');
            throw new Error('failed to fetch two factor map');
        }
    };

    useEffect(() => {
        fetchTwoFactorMap();
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
    return <AccessTokenProvider>
        <TwoFactorAuditMain />
    </AccessTokenProvider>;
};

export default TwoFactorAudit;