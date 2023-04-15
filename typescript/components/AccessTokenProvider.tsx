import { useState, useEffect } from 'react';
import * as React from 'react';

import { AccessTokenContext, readSavedAccessToken, saveAccessToken } from '../providers/access-token-provider';

export const AccessTokenProvider = ({ children }: { children: React.ReactNode }) => {
    console.debug('reading access token for the first time...');
    // eslint-disable-next-line
    const [accessToken, _] = useState(readSavedAccessToken());
    console.debug(`read ${accessToken}`);

    useEffect(() => {
        console.debug('access token has changed');
        saveAccessToken(accessToken);
    }, [accessToken]);

    return <AccessTokenContext.Provider value={accessToken}>
        { children }
    </AccessTokenContext.Provider>;
};
