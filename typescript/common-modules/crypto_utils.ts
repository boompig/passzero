import { Buffer } from "buffer";
import * as argon2 from "argon2-browser";
import { decode } from "@msgpack/msgpack";
import * as nacl from "tweetnacl";

import { IEncryptedEntry, IDecryptedEntry } from "./entries";
import { IEncryptionKeys, IKeysDatabase } from "../common-modules/passzero-api-v3";


export async function decryptEntryV5(entry: IEncryptedEntry, masterPassword: string): Promise<IDecryptedEntry> {
    const kdfSalt = Buffer.from(entry.enc_key_salt_b64, 'base64');
    const encMessage = Buffer.from(entry.enc_ciphertext_b64, 'base64');
    const nonce = Buffer.from(entry.enc_nonce_b64, 'base64');

    let start = new Date().valueOf();

    // get the per-entry key
    const entryKeyHash = await argon2.hash({
        pass: masterPassword,
        type: argon2.ArgonType.Argon2id,
        // these are taken from entries.py
        time: 2,
        mem: 65536,
        hashLen: 32,
        // specify the salt used
        salt: kdfSalt,
    });
    const entryKey = entryKeyHash.hash;

    let end = new Date().valueOf();
    console.log(`${end - start}ms to generate password for entry using argon2`);

    start = new Date().valueOf();
    const pt = nacl.secretbox.open(encMessage, nonce, entryKey);
    end = new Date().valueOf();
    console.log(`${end - start}ms to decrypt the entry`);

    start = new Date().valueOf();
    const decEntry = decode(pt) as any;
    end = new Date().valueOf();
    console.log(`${end - start}ms to decode the entry (msgpack)`);

    // copy properties from entry
    decEntry.id = entry.id;
    decEntry.account = entry.account;
    decEntry.service_link = entry.service_link;
    // set these nice static properties
    decEntry.is_encrypted = false;

    return decEntry as IDecryptedEntry;
}

export async function decryptEncryptionKeysDatabase(encryptionKeys: IEncryptionKeys, masterPassword: string): Promise<IKeysDatabase> {
    const kdfSalt = Buffer.from(encryptionKeys.enc_kdf_salt_b64, 'base64');
    const encMessage = Buffer.from(encryptionKeys.enc_contents_b64, 'base64');
    const nonce = Buffer.from(encryptionKeys.enc_nonce_b64, 'base64');

    let start = new Date().valueOf();

    const h = await argon2.hash({
        pass: masterPassword,
        type: argon2.ArgonType.Argon2id,
        time: 2,
        mem: 65536,
        hashLen: 32,
        salt: kdfSalt,
    });
    const key = h.hash;

    let end = new Date().valueOf();
    console.log(`${end - start}ms to generate password for keys database using argon2`);

    start = new Date().valueOf();
    const pt = nacl.secretbox.open(encMessage, nonce, key);
    end = new Date().valueOf();
    console.log(`${end - start}ms to decrypt the encryption DB`);

    start = new Date().valueOf();
    const keysDb = decode(pt) as IKeysDatabase;
    end = new Date().valueOf();
    console.log(`${end - start}ms to decode the keys database (msgpack)`);

    return keysDb;
}