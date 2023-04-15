export const IS_LOCAL_DEV = window.location.hostname === '127.0.0.1' || window.location.hostname === 'localhost';

/**
 * This is URL of the API server
 */
export const BASE_URL = (
    IS_LOCAL_DEV ?
        'http://localhost:5001' :
        'https://passzero.herokuapp.com'
);

export const getJSON = (path: string, queryParams?: {[key: string]: string}, extraHeaders?: {[key: string]: string}): Promise<Response> => {
    queryParams = queryParams || {};

    const url = new URL(BASE_URL);
    url.pathname = path;

    // set extra headers
    const headers = {
        'Content-Type': 'application/json',
    } as {[key: string]: string};
    if (extraHeaders) {
        Object.entries(extraHeaders).forEach(([key, value]) => {
            headers[key] = value;
        });
    }

    // set data in search params
    Object.entries(queryParams).forEach(([key, value]) => {
        url.searchParams.set(key, value);
    });

    return fetch(url.toString(), {
        method: 'GET',
        headers: headers,
        mode: 'cors',
        credentials: 'omit',
        cache: 'no-cache',
    });
};

export const postJSON = (path: string, data?: any): Promise<Response> => {
    data = data || {};

    const url = new URL(BASE_URL);
    url.pathname = path;

    return fetch(url.toString(), {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        mode: 'cors',
        cache: 'no-cache',
        credentials: 'omit',
        body: JSON.stringify(data),
    });
};
