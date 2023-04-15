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
            method: 'GET',
            headers: {
                'Content-Type': 'application/json',
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
            method: 'DELETE',
            headers: {
                'Content-Type': 'application/json',
            },
        } as RequestInit;
        return window.fetch(url, options);
    }

    async postJSON(url: string, data: any) {
        const options = {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify(data),
        } as RequestInit;
        const response = await window.fetch(url, options);
        return response.json();
    }
}
