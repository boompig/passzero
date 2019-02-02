
/**
 * Whenever you send an entry to the server, this is what is expected
 */
interface IEntryUpload {
    account: string;
    username: string;
    password: string;
    extra: string;
    has_2fa: boolean;
}

/**
 * Reflects the form in new.html for new entries
 */
interface ICreateEntryForm {
    account: string;
    username: string;
    password: string;
    extra: string;
    has_2fa: boolean;
    csrf_token: string;
}

/**
 * An existing entry that you fetch by ID
 */
interface IExistingEntry {
    account: string;
    username: string;
    password: string;
    extra: string;
    has_2fa: boolean;
    id: number;
    version: number;
}

/**
 * Reflects the form in new.html for existing entries
 * right now same as the creation form
 */
interface IEditEntryForm {
    account: string;
    username: string;
    password: string;
    extra: string;
    has_2fa: boolean;
    csrf_token: string;
}

/**
 * What an entry looks like after it's been decrypted
 */
interface IDecEntry {
    account: string;
    username: string;
    password: string;
    is_encrypted: boolean;
    has_2fa: boolean;
    id: number;
    show?: boolean;

    service_link?: string;
}

/**
 * What an entry looks like when you fetch it and it's still encrypted
 */
interface IEncEntry {
    account: string;
    is_encrypted: boolean;
    has_2fa: boolean;
    id: number;
    show?: boolean;

    service_link?: string;
}

interface IService {
    name: string;
    link: string;
    has_two_factor: boolean;
}
