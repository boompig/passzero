import { deleteSavedAccessToken } from "../providers/access-token-provider";
import { deleteSavedMasterPassword } from "../providers/master-password-provider";

export const clientSideLogout = () => {
    deleteSavedAccessToken();
    deleteSavedMasterPassword();
    window.location.assign('/login');
};