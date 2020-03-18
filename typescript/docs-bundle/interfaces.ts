export interface IEncryptedDocument {
    id: number;
    name: string;
    contents: any;

    isEncrypted: true;
}

export interface IDecryptedDocument {
    id: number;
    name: string;
    contents: any;

    isEncrypted: false;
}

export type IDocument = (IDecryptedDocument | IEncryptedDocument);