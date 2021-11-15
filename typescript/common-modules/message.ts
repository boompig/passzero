export const WEBWORKER_MSG_SOURCE = 'passzero-crypto-webworker';

/**
 * Any message sent to the crypto worker
 */
export class CryptoWorkerRcvMessage {
    constructor(
        public method: string,
        public source: string,
        public data: any,
    ) {}
}
