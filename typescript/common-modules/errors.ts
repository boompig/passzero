export class UnauthorizedError extends Error {}

export class ServerError extends Error {
    public response: Response;
    public appErrorCode: number;

    constructor(msg: string, response: Response, appErrorCode?: number) {
        super(msg);

        this.response = response;
        this.appErrorCode = appErrorCode;
    }
}

export class ApiError extends Error {
    /**
     * Denotes the specific type of error being thrown
     */
    _type: string;
    /**
     * Numerical HTTP status code
     */
    status: number;
    /**
     * Numberical app error code (see config.py)
     */
    appErrorCode: number;

    constructor(message: string, status: number, appErrorCode?: number) {
        super(message);
        this.status = status;
        this._type = 'ApiError';
        this.appErrorCode = appErrorCode || undefined;
    }
}
