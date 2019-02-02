import { UnauthorizedError } from './errors';

interface IApiKey {
    token: string;
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
        if (response.ok) {
            return response.json();
        } else {
            const text = await response.text();
            throw new UnauthorizedError(text);
        }
    }

    async postJsonWithBearer(url: string, apiToken: string, data: any) {
        const options = {
            method: "POST",
            headers: {
                "Content-Type": "application/json",
                "Authorization": `Bearer ${apiToken}`
            },
            body: JSON.stringify(data),
        } as RequestInit;
        const response = await window.fetch(url, options);
        return response.json();
    }

    async deleteWithBearer(url: string, apiToken: string) {
        const options = {
            method: "DELETE",
            headers: {
                "Content-Type": "application/json",
                "Authorization": `Bearer ${apiToken}`
            },
        } as RequestInit;
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

    async deleteEntry(entryId: number) {
        const apiToken = await this.fillToken();
        const url = `/api/v3/entries/${entryId}`;
        const response = await this.deleteWithBearer(url, apiToken);
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

    async decryptLink(linkId: number, masterPassword: string) {
        const apiToken = await this.fillToken();
        const url = `/api/v3/links/${linkId}`;
        const data = { "password": masterPassword };
        return this.postJsonWithBearer(url, apiToken, data);
    }

    async deleteLink(linkId: number) {
        const apiToken = await this.fillToken();
        const url = `/api/v3/links/${linkId}`;
        return this.deleteWithBearer(url, apiToken);
    }
}
