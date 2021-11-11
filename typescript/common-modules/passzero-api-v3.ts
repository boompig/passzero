import { UnauthorizedError, ServerError } from './errors';

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

export interface IUser {
    id: number;
    email: string;
    // ISO-encoded
    last_login: string;
    username: string | null;
    preferences: any;
}

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
        console.debug(response.headers.get("Content-Type"));
        console.debug(response.status);
        if (response.ok) {
            return response.json();
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

	async createEntry(entry: IEntry, masterPassword: string) {
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

    async decryptLink(linkId: number, masterPassword: string) {
        const apiToken = await this.fillToken();
        const url = `/api/v3/links/${linkId}`;
        const data = { "password": masterPassword };
        return this.postJsonWithBearer(url, apiToken, data);
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

    async updateCurrentUser(newFields: any) {
        const apiToken = await this.fillToken();
        const url = '/api/v3/user/me';
        return this.patchJsonWithBearer(url, apiToken, newFields);
    }
}
