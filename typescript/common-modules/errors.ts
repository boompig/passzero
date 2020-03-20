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
