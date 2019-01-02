export interface IEntry {
    is_encrypted: boolean;
    id: number;
    account: string;
}

export interface IDecryptedEntry extends IEntry {
    id: number;
    account: string;

    username: string;
    password: string;
    extra?: string;

    is_encrypted: false;
}

export interface IEncryptedEntry extends IEntry {
    id: number;
    account: string;

    is_encrypted: true;
}