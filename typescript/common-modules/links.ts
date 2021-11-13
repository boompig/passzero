export interface IDecryptedLink {
    id: number;
    user_id: number;
    link: string;
    service_name: string;
    version: number;
    is_encrypted: false;
}


export interface IEncryptedLink {
    id: number;
    user_id: number;
    version: number;
    is_encrypted: true;
    enc_kdf_salt_b64: string;
    enc_contents_b64: string;
    enc_nonce_b64: string;
}

export type ILink = (IEncryptedLink | IDecryptedLink);
