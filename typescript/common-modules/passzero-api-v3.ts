import { UnauthorizedError, ServerError, ApiError } from './errors';
import { IDecryptedLink } from './links';

interface IApiKey {
    token: string;
}

interface IEntry {
	account: string;
	username: string;
	password: string;
	extra: string;
	has_2fa: boolean;
}

export interface IEncryptionKeys {
    enc_contents_b64: string;
    enc_kdf_salt_b64: string;
    enc_nonce_b64: string;
}

export interface IKeysDatabaseEntry {
    key: BinaryData;
    last_modified: number;
}

export interface IKeysDatabase {
    entry_keys: {[key: string]: IKeysDatabaseEntry};
    link_keys: {[key: string]: IKeysDatabaseEntry};
    version: number;
}

export interface IUser {
    id: number;
    email: string;
    // ISO-encoded
    last_login: string;
    username: string | null;
    encryption_keys: IEncryptionKeys | null;

    // user preferences
    preferences: {
        default_random_password_length: number;
        default_random_passphrase_length: number;
    }
}

/**
 * If rawResponse is not defined, default to false
 */
const postJsonWithBearer = async (url: string, apiToken: string | null, data: any, rawResponse?: boolean) => {
    if(!rawResponse) {
        rawResponse = false;
    }

    const headers = {
        "Content-Type": "application/json",
    } as {[key: string]: string};

    if (apiToken) {
        headers.Authorization = `Bearer ${apiToken}`
    }

    const options = {
        method: "POST",
        headers: headers,
        body: JSON.stringify(data),
    } as RequestInit;
    const response = await window.fetch(url, options);
    if(rawResponse) {
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
        method: "DELETE",
        headers: {
            "Content-Type": "application/json",
            "Authorization": `Bearer ${apiToken}`,
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
        method: "PATCH",
        headers: {
            "Content-Type": "application/json",
            "Authorization": `Bearer ${apiToken}`
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

interface ILoginErrorResponse {
    status: string;
    msg: string;
}

interface IRegisterRequest {
    email: string;
    password: string;
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
    num_updated: number;
}

export const pzApiv3 = {
    /**
     * On success, return a parsed response
     * On error, throw ApiError
     */
    login: async (usernameOrEmail: string, password: string): Promise<ILoginResponse> => {
        const path = '/api/v3/token';
        const data = {
            password: password,
        } as ILoginRequest;
        if(usernameOrEmail.includes('@')) {
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
            if (r.headers.get('Content-Type') === 'application/json') {
                // we can read the body
                const j = (await r.json()) as ILoginErrorResponse;
                throw new ApiError(j.msg, r.status);
            } else {
                throw new ApiError('something went wrong', r.status);
            }
        }
    },

    /**
     * On success return IRegisterResponse
     * On error throw ApiError with appropriate message
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
            if (r.headers.get('Content-Type') === 'application/json') {
                // we can read the body
                const j = (await r.json()) as IRegisterResponse;
                throw new ApiError(j.msg, r.status);
            } else {
                throw new ApiError('something went wrong', r.status);
            }
        }
    },

    /**
     * @throws an API error on failure
     */
    deleteAllEntries: async (accessToken: string, masterPassword: string): Promise<IDeleteAllEntriesResponse> => {
        const path = "/api/v3/entries";
        const data = {
            password: masterPassword,
        };
        console.debug('deleting all entries...');
        const r = await deleteJsonWithBearer(path, accessToken, data);
        if (r.ok) {
            const j = await r.json();
            return j as IDeleteAllEntriesResponse;
        } else {
            if (r.headers.get('Content-Type') === 'application/json') {
                // we can read the body
                const j = (await r.json()) as IDeleteAllEntriesResponse;
                throw new ApiError(j.msg, r.status);
            } else {
                throw new ApiError('something went wrong', r.status);
            }
        }
    },

    updateEntryVersions: async (accessToken: string, masterPassword: string): Promise<IUpdateEntryVersionsResponse> => {
        const path = "/api/v3/entries";
        const data = {
            password: masterPassword,
        };
        const r = await patchJsonWithBearer(path, accessToken, data);
        if (r.ok) {
            const j = await r.json();
            return j as IUpdateEntryVersionsResponse;
        } else {
            if (r.headers.get('Content-Type') === 'application/json') {
                // we can read the body
                const j = (await r.json()) as IDeleteAllEntriesResponse;
                throw new ApiError(j.msg, r.status);
            } else {
                throw new ApiError('something went wrong', r.status);
            }
        }
    },
};


export default class PasszeroApiV3 {
    private apiKey: (IApiKey | null);

    constructor() {
        this.apiKey = null;
    }

    async getJsonWithBearer(url: string, apiToken?: string) {
        const options = {
            method: "GET",
            headers: {
                "Content-Type": "application/json",
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
        } else if(response.status == 500 && response.headers.get("Content-Type") === "application/json") {
            const j = await response.json();
            throw new ServerError(j.msg, response, j.app_error_code);
        } else {
            const text = await response.text();
            throw new UnauthorizedError(text);
        }
    }

	/**
	 * If rawResponse is not defined, default to false
	 */
	async postJsonWithBearer(url: string, apiToken: string, data: any, rawResponse?: boolean) {
		if(!rawResponse) {
			rawResponse = false;
		}
        const options = {
            method: "POST",
            headers: {
                "Content-Type": "application/json",
                "Authorization": `Bearer ${apiToken}`
            },
            body: JSON.stringify(data),
        } as RequestInit;
		const response = await window.fetch(url, options);
		if(rawResponse) {
			return response;
		} else {
			return response.json();
		}
	}

	/**
	 * If rawResponse is not defined, default to false
	 */
	async patchJsonWithBearer(url: string, apiToken: string, data: any, rawResponse?: boolean) {
		if(!rawResponse) {
			rawResponse = false;
		}
        const options = {
            method: "PATCH",
            headers: {
                "Content-Type": "application/json",
                "Authorization": `Bearer ${apiToken}`
            },
            body: JSON.stringify(data),
        } as RequestInit;
		const response = await window.fetch(url, options);
		if(rawResponse) {
			return response;
		} else {
			return response.json();
		}
    }

    async deleteWithBearer(url: string, apiToken: string, data?: any) {
        const options = {
            method: "DELETE",
            headers: {
                "Content-Type": "application/json",
                "Authorization": `Bearer ${apiToken}`
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
     * 		1. if this.apiKey is set, set the token from that
     * 		2. Make a requrest to getToken to get a new API key and set the token that way
     */
    async fillToken() {
        if (this.apiKey) {
            return this.apiKey.token;
        }
        const apiKey = await this.getToken();
        this.apiKey = apiKey;
        return apiKey.token;
    }

    /**
     * If we have a 401 error response, throw UnauthorizedError
     */
    async getToken() {
        const url = "/api/v3/token";
        return this.getJsonWithBearer(url);
	}

	/* services */

	async getServices() {
		const url = "/api/v3/services";
		return this.getJsonWithBearer(url);
	}

    /* entries */

    async getEncryptedEntries() {
        const apiToken = await this.fillToken();
        const url = "/api/v3/entries";
        const response = await this.getJsonWithBearer(url, apiToken);
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
		const url = "/api/v3/entries";
		const data = {
			entry: entry,
			password: masterPassword
		};
		const response = await this.postJsonWithBearer(url, apiToken, data, true);
		return response;
	}

	async updateEntry(entryId: number, entry: IEntry, masterPassword: string) {
		const apiToken = await this.fillToken();
		const url = `/api/v3/entries/${entryId}`;
		const data = {
			entry: entry,
			password: masterPassword
		};
		const response = await this.patchJsonWithBearer(url, apiToken, data, true);
		return response;
	}

    /* links */

    async getEncryptedLinks() {
        const apiToken = await this.fillToken();
        const url = "/api/v3/links";
        return this.getJsonWithBearer(url, apiToken);
    }

    async saveLink(linkData: any) {
        const apiToken = await this.fillToken();
        const url = "/api/v3/links";
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
        const data = { "password": masterPassword };
        const decLink = (await this.postJsonWithBearer(url, apiToken, data)) as any;
        decLink.is_encrypted = false;
        return decLink;
    }

    async decryptLinks(linkIds: number[], masterPassword: string) {
        const apiToken = await this.fillToken();
        const url = `/api/v3/links/decrypt`;
        const data = {
            "password": masterPassword,
            "link_ids": linkIds,
        };
        return this.postJsonWithBearer(url, apiToken, data);
    }

    async deleteLink(linkId: number, masterPassword: string) {
        const apiToken = await this.fillToken();
        const url = `/api/v3/links/${linkId}`;
        const data = {
            password: masterPassword,
        }
        return this.deleteWithBearer(url, apiToken, data);
    }

    async getCurrentUser(): Promise<IUser> {
        const apiToken = await this.fillToken();
        const url = '/api/v3/user/me';
        const user = await this.getJsonWithBearer(url, apiToken);
        // user.last_login = new Date(user.last_login)
        return user as IUser;
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
        const url = "/api/v3/user/password";
        const data = {
            "old_password": oldPassword,
            "new_password": newPassword,
            "confirm_new_password": confirmNewPassword,
        };
        const r = await this.postJsonWithBearer(url, apiToken, data, true) as Response;
        return r;
    }

    async deleteAccount(masterPassword: string): Promise<Response> {
        const apiToken = await this.fillToken();
        const url = "/api/v3/user/delete";
        const data = {
            "password": masterPassword,
        };
        const r = await this.postJsonWithBearer(url, apiToken, data, true) as Response;
        return r;
    }
}
