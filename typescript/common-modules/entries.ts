/**
 * Common properties between encrypted and decrypted entry
 */
export interface IEntry {
    // eslint-disable-next-line
    is_encrypted: boolean;
    id: number;
    account: string;

    // eslint-disable-next-line
    service_link?: string;
}

/**
 * Meant to exactly match decrypted Entry to_json serialization
 */
export interface IDecryptedEntry extends IEntry {
    id: number;
    account: string;

    username: string;
    password: string;
    extra?: string;

    /*
     * This is present only for entries with version 5+
     * The value is a PYTHON timestamp
     * To convert to a JAVASCRIPT timestamp, need to multiply by 1000
     */
    // eslint-disable-next-line
    last_modified?: number;

    // eslint-disable-next-line
    is_encrypted: false;

    // eslint-disable-next-line
    service_link?: string;

    // eslint-disable-next-line
    has_2fa?: boolean;

    /**
     * Version of the entry
     */
    version: number;
}

export interface IEncryptedEntry extends IEntry {
    id: number;
    account: string;

    // eslint-disable-next-line
    is_encrypted: true;
    version: number;

    // more recent entries support client-side decryption
    // these entries will return their encrypted contents in base64-encoded form
    // eslint-disable-next-line
    enc_ciphertext_b64?: string;
    // eslint-disable-next-line
    enc_key_salt_b64?: string;
    // eslint-disable-next-line
    enc_nonce_b64?: string;

    // eslint-disable-next-line
    service_link?: string;
}
