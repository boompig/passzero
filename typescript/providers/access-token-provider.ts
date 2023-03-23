// import * as React from 'react';
import { createContext } from 'react';

/**
 * The token is stored as a text string
 */
export const readSavedAccessToken = () => {
    const token = window.localStorage.getItem('access_token');
    return token;
};

export const deleteSavedAccessToken = () => {
    window.localStorage.removeItem('access_token');
};

// TODO - is this the right thing?
export const saveAccessToken = (accessToken: string) => {
    console.debug(`Setting new access token: ${accessToken}...`);
    window.localStorage.setItem('access_token', accessToken);
    console.debug('new access token has been set');
};

export const AccessTokenContext = createContext('');