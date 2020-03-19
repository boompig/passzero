export interface IEntry {
    is_encrypted: boolean;
    id: number;
    account: string;

    service_link?: string;
}

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
    last_modified?: number;

    is_encrypted: false;

    service_link?: string;
}

export interface IEncryptedEntry extends IEntry {
    id: number;
    account: string;

    is_encrypted: true;

    service_link?: string;
}
