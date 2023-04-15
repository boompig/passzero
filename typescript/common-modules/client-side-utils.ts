import { deleteSavedAccessToken } from '../providers/access-token-provider';
import { deleteSavedMasterPassword } from '../providers/master-password-provider';

export const clientSideLogout = () => {
    deleteSavedAccessToken();
    deleteSavedMasterPassword();
    // TODO - have a back-reference to the current page
    window.location.assign('/login');
};
