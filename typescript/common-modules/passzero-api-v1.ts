/**
 * yes, I do know that there is another file in common
 * This is an attempt to rewrite it for those sections of the site that use react
 */

import { UnauthorizedError } from './errors';


/**
 * NOTE: do not use this! This API is deprecated.
 * @deprecated
 */
export default class PassZeroAPIv1 {
    constructor() {
        this.getJSON = this.getJSON.bind(this);
    }

    async getJSON(url: string) {
        const options = {
            method: "GET",
            headers: {
                "Content-Type": "application/json",
            },
        } as RequestInit;
        const response = await window.fetch(url, options);
        if (response.ok) {
            return response.json();
        } else {
            const text = await response.text();
            throw new UnauthorizedError(text);
        }
    }

    async deleteJSON(url: string): Promise<Response> {
        const options = {
            method: "DELETE",
            headers: {
                "Content-Type": "application/json",
            },
        } as RequestInit;
        return window.fetch(url, options);
    }

	async postJSON(url: string, data: any) {
        const options = {
            method: "POST",
            headers: {
                "Content-Type": "application/json",
            },
            body: JSON.stringify(data),
        } as RequestInit;
		const response = await window.fetch(url, options);
        return response.json();
    }

    async postFile(url: string, formData: FormData): Promise<Response> {
        return window.fetch(url, {
            method: "POST",
            body: formData
        });
    }

    async putFile(url: string, formData: FormData): Promise<Response> {
        return window.fetch(url, {
            method: "PUT",
            body: formData
        });
    }

    async getCSRFToken() {
        const url = "/api/v1/csrf_token";
        return this.getJSON(url);
    }

    /**
     * Returns the JSON response, not the Response object
     * In the case of error, throws an error
     */
    async getEncryptedDocuments() {
        const url = "/api/v1/docs";
        return this.getJSON(url);
    }

    async createDocument(fileName: string, formData: FormData): Promise<Response> {
        const url = "/api/v1/docs";
        const file = formData.get("document") as File;
        // add CSRF
        const token = await this.getCSRFToken();
        formData.set("name", fileName);
        formData.set("csrf_token", token);
        formData.set("mimetype", file.type);
        return this.postFile(url, formData);
    }

    async updateDocument(id: number, fileName: string, formData: FormData): Promise<Response> {
        const url = `/api/v1/docs/${id}`;
        const file = formData.get("document") as File;
        // add CSRF
        const token = await this.getCSRFToken();
        formData.set("name", fileName);
        formData.set("csrf_token", token);
        formData.set("mimetype", file.type);
        return this.putFile(url, formData);
    }

    async deleteDocument(id: number): Promise<Response> {
        window.location.host
        const url = new URL(window.location.origin);
        url.pathname = `/api/v1/docs/${id}`;
        const token = await this.getCSRFToken();
        url.searchParams.append("csrf_token", token);
        return this.deleteJSON(url.toString());
    }
}