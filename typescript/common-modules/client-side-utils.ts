import { deleteSavedAccessToken } from '../providers/access-token-provider';
import { deleteSavedMasterPassword } from '../providers/master-password-provider';

export const clientSideLogout = () => {
    deleteSavedAccessToken();
    deleteSavedMasterPassword();
    // TODO - have a back-reference to the current page
    // TODO for now redirect to the logout handler which also destroys the server-side session
    window.location.assign('/logout');
};
