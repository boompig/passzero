/**
 * yes, I do know that there is another file in common
 * This is an attempt to rewrite it for those sections of the site that use react
 */

import { UnauthorizedError } from './errors';

export default class PassZeroAPIv1 {
    constructor() {
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

    async getCSRFToken() {
        const url = pzAPI.base_url + "/api/v1/csrf_token";
        return pzAPI.getJSON(url);
    }

    async getEncryptedDocuments() {
        const url = "/api/v1/docs";
        return this.getJSON(url);
    }

    async decryptDocument(id: number) {
        const url = `/api/v1/docs/${id}`;
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
}