/**
 * This is our WebWorker which performs background cryptographic tasks
 * See: https://developer.mozilla.org/en-US/docs/Web/API/Web_Workers_API/Using_web_workers
 */

import { decryptEncryptionKeysDatabase } from '../common-modules/crypto-utils';
import { CryptoWorkerRcvMessage, WEBWORKER_MSG_SOURCE } from '../common-modules/message';
import { IEncryptionKeys } from '../common-modules/passzero-api-v3';


const ALLOWED_MSG_SOURCES = ['entries-bundle'];

const handleDecryptEncryptionKeysDatabase = async (message: CryptoWorkerRcvMessage) => {
    // compute
    try {
        const keysDB = await decryptEncryptionKeysDatabase(
            message.data.encryption_keys as IEncryptionKeys,
            message.data.master_password as string,
        );
        console.log('keys database has been decrypted');
        // reply
        postMessage({
            source: WEBWORKER_MSG_SOURCE,
            method: message.method,
            data: {
                keysDB,
            },
        });
    } catch (err) {
        console.error('Failed to decrypt encryption keys database locally');
        console.error(err);
    }
};

const handleCryptoWorkerMessage = (message: CryptoWorkerRcvMessage) => {
    console.debug('Received message from main thread');
    console.debug(message);

    switch (message.method) {
        case 'decryptEncryptionKeysDatabase': {
            handleDecryptEncryptionKeysDatabase(message);
            break;
        }
        default: {
            console.error(`Got invalid method in worker thread: ${message.method}`);
            break;
        }
    }
};

/**
 * This is the main dispatcher of the web crypto worker
 */
onmessage = function (event: MessageEvent) {
    if (event.data.source && ALLOWED_MSG_SOURCES.includes(event.data.source) && event.data.method) {
        handleCryptoWorkerMessage(event.data as CryptoWorkerRcvMessage);
    } else {
        console.debug('Received message from a different thread');
        console.debug(event.data);
    }
}
