/**
 * See the links python model
 */
export interface IDecryptedLink {
    id: number;
    // eslint-disable-next-line
    user_id: number;
    link: string;
    // eslint-disable-next-line
    service_name: string;
    version: number;
    // eslint-disable-next-line
    is_encrypted: false;
}

/**
 * See the links python model
 */
export interface IEncryptedLink {
    id: number;
    // eslint-disable-next-line
    user_id: number;
    version: number;
    // eslint-disable-next-line
    is_encrypted: true;
    // eslint-disable-next-line
    enc_kdf_salt_b64: string;
    // eslint-disable-next-line
    enc_ciphertext_b64: string;
    // eslint-disable-next-line
    enc_nonce_b64: string;
}

export type ILink = (IEncryptedLink | IDecryptedLink);
