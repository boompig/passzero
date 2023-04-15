import { createContext } from 'react';

// utility to read
export const readSavedMasterPassword = () => {
    const masterPassword = window.localStorage.getItem('master_password');
    return masterPassword;
};

// utility to delete
export const deleteSavedMasterPassword = () => {
    window.localStorage.removeItem('master_password');
};

// TODO - is this the right thing?
export const saveMasterPassword = (masterPassword: string) => {
    window.localStorage.setItem('master_password', masterPassword);
};

// actually read it and create a context
const masterPassword = readSavedMasterPassword();
export const MasterPasswordContext = createContext({
    masterPassword: masterPassword,
    // eslint-disable-next-line
    setMasterPassword: (newMasterPassword: string | null) => {},
});
