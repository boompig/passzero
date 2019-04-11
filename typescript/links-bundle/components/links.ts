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
}

export type ILink = (IEncryptedLink | IDecryptedLink);
