import { saveAccessToken } from '../providers/access-token-provider';
import { IDecryptedEntry, IEncryptedEntry } from './entries';
import { UnauthorizedError, ServerError, ApiError } from './errors';
import { IDecryptedLink, IEncryptedLink } from './links';

interface IApiKey {
    token: string;
}

/**
 * Exactly mirrors entry model
 */
interface IEntry {
    account: string;
    username: string;
    password: string;
    extra: string;
    // eslint-disable-next-line
    has_2fa: boolean;
}

export interface IEncryptionKeys {
    // eslint-disable-next-line
    enc_contents_b64: string;
    // eslint-disable-next-line
    enc_kdf_salt_b64: string;
    // eslint-disable-next-line
    enc_nonce_b64: string;
}

export interface IKeysDatabaseEntry {
    key: BinaryData;
    // eslint-disable-next-line
    last_modified: number;
}

export interface IKeysDatabase {
    // eslint-disable-next-line
    entry_keys: {[key: string]: IKeysDatabaseEntry};
    // eslint-disable-next-line
    link_keys: {[key: string]: IKeysDatabaseEntry};
    version: number;
}

export interface IUser {
    id: number;
    email: string;
    // ISO-encoded
    // eslint-disable-next-line
    last_login: string;
    username: string | null;
    // eslint-disable-next-line
    encryption_keys: IEncryptionKeys | null;

    // user preferences
    preferences: {
        // eslint-disable-next-line
        default_random_password_length: number;
        // eslint-disable-next-line
        default_random_passphrase_length: number;
    }
}

const getJsonWithBearer = async (path: string, apiToken: string | null, queryParams: { [key: string]: string | number | boolean },
    rawResponse: boolean): Promise<Response> => {
    if (!rawResponse) {
        throw new Error('for now raw response must be set');
    }

    const url = new URL(window.location.href);
    url.pathname = path;
    url.hash = '';

    if (queryParams) {
        Object.entries(queryParams).forEach(([key, value]) => {
            url.searchParams.set(key, value.toString());
        });
    }

    const options = {
        method: 'GET',
        headers: {
            'Content-Type': 'application/json',
        },
        // TODO: this is just temporary
        credentials: 'same-origin',
    } as RequestInit;
    if (apiToken) {
        (options.headers as any).Authorization = `Bearer ${apiToken}`;
    }
    const response = await window.fetch(url.toString(), options);
    return response;
};

/**
 * If rawResponse is not defined, default to false
 */
const postJsonWithBearer = async (url: string, apiToken: string | null, data: any, rawResponse?: boolean): Promise<Response> => {
    if (!rawResponse) {
        rawResponse = false;
    }

    const headers = {
        'Content-Type': 'application/json',
    } as {[key: string]: string};

    if (apiToken) {
        headers.Authorization = `Bearer ${apiToken}`;
    }

    const options = {
        method: 'POST',
        headers: headers,
        body: JSON.stringify(data),
    } as RequestInit;
    const response = await window.fetch(url, options);
    if (rawResponse) {
        return response;
    } else {
        return response.json();
    }
};

const deleteJsonWithBearer = async (path: string, apiToken: string, queryParams: {[key: string]: string}): Promise<Response> => {
    // const url = new URL(BASE_URL);
    const url = new URL(window.location.href);
    url.pathname = path;
    // reset hash
    url.hash = '';

    const options = {
        method: 'DELETE',
        headers: {
            'Content-Type': 'application/json',
            'Authorization': `Bearer ${apiToken}`,
        },
        mode: 'cors',
        credentials: 'omit',
        cache: 'no-cache',
    } as RequestInit;
    if (queryParams) {
        Object.entries(queryParams).forEach(([key, value]) => {
            url.searchParams.set(key, value);
        });
    }
    // console.debug(`Using BASE_URL ${BASE_URL}`);
    const response = await window.fetch(url.toString(), options);
    return response;
};

/**
 * If rawResponse is not defined, default to false
 */
const patchJsonWithBearer = async (path: string, apiToken: string, data: any): Promise<Response> => {
    // const url = new URL(BASE_URL);
    const url = new URL(window.location.href);
    url.pathname = path;
    url.hash = '';

    const options = {
        method: 'PATCH',
        headers: {
            'Content-Type': 'application/json',
            'Authorization': `Bearer ${apiToken}`,
        },
        body: JSON.stringify(data),
        credentials: 'omit',
        mode: 'cors',
        cache: 'no-cache',
    } as RequestInit;
    const response = await window.fetch(url.toString(), options);
    return response;
};

interface ILoginRequest {
    email?: string;
    username?: string;
    password: string;
}

interface ILoginResponse {
    token: string;
}

interface IRegisterRequest {
    email: string;
    password: string;
    // eslint-disable-next-line
    confirm_password: string;
}

/**
 * This occurs on both success and failure
 */
interface IRegisterResponse {
    status: string;
    msg: string;
}

interface IUpdateUserResponse {
    status: string;
    msg: string;
}

/**
 * This occurs on both success and failure
 */
interface IDeleteAllEntriesResponse {
    status: string;
    msg: string;
}

/**
 * On success
 */
interface IUpdateEntryVersionsResponse {
    status: string;
    // eslint-disable-next-line
    num_updated: number;
    version: number;
}

interface ITokenResponse {
    token: string;
}

interface IService {
    name: string;
    link: string;
    // eslint-disable-next-line
    has_two_factor: boolean;
}

interface IServicesResponse {
    services: IService[];
}

interface IEncryptedEntriesResponse {
    entries: IEncryptedEntry[];
    // eslint-disable-next-line
    latest_version: number;
}

/**
 * This is the standard format for basically any error that the API throws
 */
interface IStandardErrorResponse {
    msg: string;
    status: string;
    /**
     * This is not always set. Helps differentiate between different error scenarios.
     * More reliable than parsing the error text.
     */
    code?: number;
}

async function parseApiError(r: Response, defaultMessage: string): Promise<ApiError> {
    if (r.headers.get('Content-Type') === 'application/json') {
        // we can read the body
        const j = (await r.json()) as IStandardErrorResponse;
        if (j.msg) {
            return new ApiError(j.msg, r.status, j.code || undefined);
        } else {
            console.error('did not get msg field from API on error');
            return new ApiError(defaultMessage, r.status);
        }
    } else {
        console.error('got unexpected Content-Type from API on error');
        return new ApiError(defaultMessage, r.status);
    }
}

interface IRegisterConfirmResponse {
    status: string;
    msg: string;
}

interface IExportTokenResponse {
    token: string;
}

export const pzApiv3 = {
    /**
     * Get the token using an existing session-cookie
     */
    async getToken(): Promise<string> {
        const path = '/api/v3/token';
        const r = await getJsonWithBearer(path, null, null, true);
        if (r.ok) {
            const j = (await r.json()) as ITokenResponse;
            const token = j.token;
            return token;
        } else {
            if (r.headers.get('Content-Type') === 'application/json') {
                const j = await r.json();
                throw new ApiError(j.msg, r.status);
            } else {
                throw new ApiError('Unknown error when fetching token', r.status);
            }
        }
    },

    /**
     * On success, return a parsed response
     * On error, throw ApiError
     */
    login: async (usernameOrEmail: string, password: string): Promise<ILoginResponse> => {
        const path = '/api/v3/token';
        const data = {
            password: password,
        } as ILoginRequest;
        if (usernameOrEmail.includes('@')) {
            console.debug('logging in with email...');
            data.email = usernameOrEmail;
        } else {
            console.debug('logging in with username...');
            data.username = usernameOrEmail;
        }

        const r = await postJsonWithBearer(path, null, data, true);
        if (r.ok) {
            const j = await r.json();
            return j as ILoginResponse;
        } else {
            const err = await parseApiError(r, 'Failed to login.');
            throw err;
        }
    },

    /**
     * Step 1 of the user registration flow
     * On success return IRegisterResponse
     * @throws {ApiError} on failure
     */
    registerUser: async (email: string, password: string, confirmPassword: string): Promise<IRegisterResponse> => {
        const path = '/api/v3/user/register';

        const data = {
            email: email,
            password: password,
            confirm_password: confirmPassword,
        } as IRegisterRequest;

        const r = await postJsonWithBearer(path, null, data, true);
        if (r.ok) {
            const j = (await r.json()) as IRegisterResponse;
            return j;
        } else {
            const err = await parseApiError(r, 'Failed to register user.');
            throw err;
        }
    },

    /**
     * Step 2 of the user registration flow
     * @throws {ApiError} on failure
     */
    registerUserConfirm: async (token: string): Promise<IRegisterConfirmResponse> => {
        const path = '/api/v3/user/register/confirm';

        const data = {
            token: token,
        };

        const r = await postJsonWithBearer(path, null, data, true);
        if (r.ok) {
            const j = (await r.json()) as IRegisterConfirmResponse;
            return j;
        } else {
            const err = await parseApiError(r, 'Failed to confirm user registration.');
            throw err;
        }
    },

    /**
     * @throws {ApiError} on failure
     */
    deleteAllEntries: async (accessToken: string, masterPassword: string): Promise<IDeleteAllEntriesResponse> => {
        const path = '/api/v3/entries';
        const data = {
            password: masterPassword,
        };
        console.debug('deleting all entries...');
        const r = await deleteJsonWithBearer(path, accessToken, data);
        if (r.ok) {
            const j = await r.json();
            return j as IDeleteAllEntriesResponse;
        } else {
            const err = await parseApiError(r, 'Failed to delete all entries.');
            throw err;
        }
    },

    /**
     * @throws {ApiError} on failure
     */
    updateEntryVersions: async (accessToken: string, masterPassword: string): Promise<IUpdateEntryVersionsResponse> => {
        const path = '/api/v3/entries';
        const data = {
            password: masterPassword,
        };
        const r = await patchJsonWithBearer(path, accessToken, data);
        if (r.ok) {
            const j = await r.json();
            return j as IUpdateEntryVersionsResponse;
        } else {
            const err = await parseApiError(r, 'Failed to update entry versions.');
            throw err;
        }
    },

    /**
     * Step 1 of the account recovery flow
     */
    recoverAccountStart: async (email: string, acceptRisks: boolean): Promise<Response> => {
        const path = '/api/v3/recover';
        const data = {
            email: email,
            accept_risks: acceptRisks,
        };
        return postJsonWithBearer(path, null, data, true);
    },

    recoveryGetEmailWithToken: async (token: string): Promise<Response> => {
        const path = '/api/v3/recover/email';
        const data = {
            token: token,
        };
        return getJsonWithBearer(path, null, data, true);
    },

    /**
     * Step 2 of the recovery flow
     */
    recoverAccountConfirm: async (token: string, password: string, confirmPassword: string, acceptRisks: boolean): Promise<Response> => {
        const path = '/api/v3/recover/confirm';
        const data = {
            token: token,
            password: password,
            confirm_password: confirmPassword,
            accept_risks: acceptRisks,
        };
        return postJsonWithBearer(path, null, data, true);
    },

    getPasswordStrengthScores: async (accessToken: string, password: string): Promise<Response> => {
        if (!password) {
            throw new Error('password is required');
        }
        const path = '/api/v3/entries/password-strength';
        const data = {
            password: password,
        };
        return getJsonWithBearer(path, accessToken, data, true);
    },

    getTwoFactorAudit: async (accessToken: string): Promise<Response> => {
        const path = '/api/v3/entries/two-factor-audit';
        const data = {};
        return await getJsonWithBearer(path, accessToken, data, true);
    },

    getCurrentUser: async (accessToken: string): Promise<IUser> => {
        const path = '/api/v3/user/me';
        const params = {};
        const r = await getJsonWithBearer(path, accessToken, params, true);
        if (r.ok) {
            const j = await r.json() as IUser;
            return j;
        } else {
            const err = await parseApiError(r, 'Failed to get current user details');
            throw err;
        }
    },

    getEncryptedEntries: async (accessToken: string): Promise<IEncryptedEntriesResponse> => {
        const path = '/api/v3/entries';
        const params = {};
        console.debug('Getting encrypted entries...');
        const r = await getJsonWithBearer(path, accessToken, params, true);
        if (r.ok) {
            const j = await r.json() as IEncryptedEntriesResponse;
            return j;
        } else {
            const err = await parseApiError(r, 'Failed to get encrypted entries');
            throw err;
        }
    },

    decryptEntry: async (accessToken: string, entryId: number, masterPassword: string): Promise<IDecryptedEntry> => {
        const path = `/api/v3/entries/${entryId}`;
        const data = {
            password: masterPassword,
        };
        const r = await postJsonWithBearer(path, accessToken, data, true);
        if (r.ok) {
            const j = await r.json() as IDecryptedEntry;
            return j;
        } else {
            const err = await parseApiError(r, 'Failed to decrypt entry.');
            throw err;
        }
    },

    getExportToken: async (accessToken: string, masterPassword: string): Promise<IExportTokenResponse> => {
        const path = `/api/v3/entries/export`;
        const data = {
            password: masterPassword,
        };
        const r = await postJsonWithBearer(path, accessToken, data, true);
        if (r.ok) {
            const j = await r.json() as IExportTokenResponse;
            return j;
        } else {
            const err = await parseApiError(r, 'Failed to get token for entries export.');
            throw err;
        }
    },
};


export default class PasszeroApiV3 {
    private apiKey: (IApiKey | null);

    constructor() {
        this.apiKey = null;
    }

    async getJsonWithBearer<T>(url: string, apiToken?: string): Promise<T> {
        const options = {
            method: 'GET',
            headers: {
                'Content-Type': 'application/json',
            },
        } as RequestInit;
        if (apiToken) {
            (options.headers as any).Authorization = `Bearer ${apiToken}`;
        }
        const response = await window.fetch(url, options);
        // console.debug(response.headers.get("Content-Type"));
        // console.debug(response.status);
        if (response.ok) {
            return response.json();
        } else if (response.status === 401) {
            const text = await response.text();
            throw new UnauthorizedError(text);
        } else if (response.status === 500 && response.headers.get('Content-Type') === 'application/json') {
            const j = await response.json();
            throw new ServerError(j.msg, response, j.app_error_code || undefined);
        } else {
            const text = await response.text();
            throw new UnauthorizedError(text);
        }
    }

    /**
     * If rawResponse is not defined, default to false
     */
    async postJsonWithBearer(url: string, apiToken: string, data: any, rawResponse?: boolean) {
        if (!rawResponse) {
            rawResponse = false;
        }
        const options = {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${apiToken}`,
            },
            body: JSON.stringify(data),
        } as RequestInit;
        const response = await window.fetch(url, options);
        if (rawResponse) {
            return response;
        } else {
            return response.json();
        }
    }

    /**
     * If rawResponse is not defined, default to false
     */
    async patchJsonWithBearer(url: string, apiToken: string, data: any, rawResponse?: boolean) {
        if (!rawResponse) {
            rawResponse = false;
        }
        const options = {
            method: 'PATCH',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${apiToken}`,
            },
            body: JSON.stringify(data),
        } as RequestInit;
        const response = await window.fetch(url, options);
        if (rawResponse) {
            return response;
        } else {
            return response.json();
        }
    }

    async deleteWithBearer(url: string, apiToken: string, data?: any) {
        const options = {
            method: 'DELETE',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${apiToken}`,
            },
        } as RequestInit;
        if (data) {
            // set data only when it's present
            options.body = JSON.stringify(data);
        }
        const response = await window.fetch(url, options);
        if (response.ok) {
            return response.json();
        } else {
            const text = await response.text();
            throw new Error(text);
        }
    }

    /**
     * If the token is not provided in the function, then (in order of precedence)
     * 1. if this.apiKey is set, set the token from that
     * 2. Make a requrest to getToken to get a new API key and set the token that way
     */
    async fillToken() {
        if (this.apiKey) {
            return this.apiKey.token;
        }
        const apiKey = await this.getToken();
        if (apiKey && apiKey.token) {
            // TODO
            // also save it to localStorage
            saveAccessToken(apiKey.token);
        }
        this.apiKey = apiKey;
        return apiKey.token;
    }

    /**
     * If we have a 401 error response, throw UnauthorizedError
     */
    async getToken() {
        const url = '/api/v3/token';
        return this.getJsonWithBearer<ITokenResponse>(url);
    }

    /* services */

    async getServices() {
        const url = '/api/v3/services';
        return this.getJsonWithBearer<IServicesResponse>(url);
    }

    /* entries */

    async getEncryptedEntries() {
        const apiToken = await this.fillToken();
        const url = '/api/v3/entries';
        const response = await this.getJsonWithBearer<IEncryptedEntriesResponse>(url, apiToken);
        return response;
    }

    async deleteEntry(entryId: number, masterPassword: string) {
        const apiToken = await this.fillToken();
        const url = `/api/v3/entries/${entryId}`;
        const data = {
            password: masterPassword,
        };
        const response = await this.deleteWithBearer(url, apiToken, data);
        return response;
    }

    async decryptEntry(entryId: number, masterPassword: string) {
        const apiToken = await this.fillToken();
        const url = `/api/v3/entries/${entryId}`;
        const data = {
            password: masterPassword,
        };
        const response = await this.postJsonWithBearer(url, apiToken, data);
        return response;
    }

    /**
     * Return the raw response
     */
    async createEntry(entry: IEntry, masterPassword: string): Promise<Response> {
        const apiToken = await this.fillToken();
        const url = '/api/v3/entries';
        const data = {
            entry: entry,
            password: masterPassword,
        };
        const response = await this.postJsonWithBearer(url, apiToken, data, true);
        return response;
    }

    async updateEntry(entryId: number, entry: IEntry, masterPassword: string) {
        const apiToken = await this.fillToken();
        const url = `/api/v3/entries/${entryId}`;
        const data = {
            entry: entry,
            password: masterPassword,
        };
        const response = await this.patchJsonWithBearer(url, apiToken, data, true);
        return response;
    }

    /* links */

    async getEncryptedLinks() {
        const apiToken = await this.fillToken();
        const url = '/api/v3/links';
        return this.getJsonWithBearer<IEncryptedLink[]>(url, apiToken);
    }

    async saveLink(linkData: any) {
        const apiToken = await this.fillToken();
        const url = '/api/v3/links';
        return this.postJsonWithBearer(url, apiToken, linkData);
    }

    async editLink(linkId: number, linkData: any) {
        const apiToken = await this.fillToken();
        const url = `/api/v3/links/${linkId}`;
        return this.patchJsonWithBearer(url, apiToken, linkData);
    }

    async decryptLink(linkId: number, masterPassword: string): Promise<IDecryptedLink> {
        const apiToken = await this.fillToken();
        const url = `/api/v3/links/${linkId}`;
        const data = { 'password': masterPassword };
        const decLink = (await this.postJsonWithBearer(url, apiToken, data)) as any;
        decLink.is_encrypted = false;
        return decLink;
    }

    async decryptLinks(linkIds: number[], masterPassword: string) {
        const apiToken = await this.fillToken();
        const url = `/api/v3/links/decrypt`;
        const data = {
            'password': masterPassword,
            'link_ids': linkIds,
        };
        return this.postJsonWithBearer(url, apiToken, data);
    }

    async deleteLink(linkId: number, masterPassword: string) {
        const apiToken = await this.fillToken();
        const url = `/api/v3/links/${linkId}`;
        const data = {
            password: masterPassword,
        };
        return this.deleteWithBearer(url, apiToken, data);
    }

    async getCurrentUser(): Promise<IUser> {
        const apiToken = await this.fillToken();
        const url = '/api/v3/user/me';
        return this.getJsonWithBearer<IUser>(url, apiToken);
        // user.last_login = new Date(user.last_login)
        // return user as IUser;
    }

    /**
     * On success return the status and message
     * On error throw an ApiError
     * @throws {ApiError}
     */
    async updateCurrentUser(newFields: any): Promise<IUpdateUserResponse> {
        const apiToken = await this.fillToken();
        const url = '/api/v3/user/me';
        const r = await this.patchJsonWithBearer(url, apiToken, newFields, true) as Response;
        if (r.ok) {
            const j = await r.json();
            return j as IUpdateUserResponse;
        } else {
            if (r.headers.get('Content-Type') === 'application/json') {
                // we can read the body
                const j = (await r.json()) as IRegisterResponse;
                throw new ApiError(j.msg, r.status);
            } else {
                throw new ApiError('something went wrong', r.status);
            }
        }
    }

    async changePassword(oldPassword: string, newPassword: string, confirmNewPassword: string): Promise<Response> {
        const apiToken = await this.fillToken();
        const url = '/api/v3/user/password';
        const data = {
            'old_password': oldPassword,
            'new_password': newPassword,
            'confirm_new_password': confirmNewPassword,
        };
        const r = await this.postJsonWithBearer(url, apiToken, data, true) as Response;
        return r;
    }

    async deleteAccount(masterPassword: string): Promise<Response> {
        const apiToken = await this.fillToken();
        const url = '/api/v3/user/delete';
        const data = {
            'password': masterPassword,
        };
        const r = await this.postJsonWithBearer(url, apiToken, data, true) as Response;
        return r;
    }
}
