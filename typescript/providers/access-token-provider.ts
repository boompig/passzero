import { createContext } from 'react';

export const readSavedAccessToken = () => {
    const token = window.localStorage.getItem('access_token');
    return token;
};

export const deleteSavedAccessToken = () => {
    window.localStorage.removeItem('access_token');
};

// TODO - is this the right thing?
export const saveAccessToken = (accessToken: string) => {
    window.localStorage.setItem('access_token', accessToken);
};
                                                                                                                                                                                      const token = readSavedAccessToken();
export const AccessTokenContext = createContext({
    accessToken: token,
    // eslint-disable-next-line
    setAccessToken: (newToken: string | null) => {},
});