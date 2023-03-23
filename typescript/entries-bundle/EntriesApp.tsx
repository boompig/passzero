/**
 * This is the top-level component for the PassZero application
 */

import { Component } from "react";
import * as React from "react";

import DecryptedEntry from "./components/decrypted-entry";
import EncryptedEntry from "./components/encrypted-entry";
import {IDecryptedEntry, IEncryptedEntry, IEntry} from "../common-modules/entries";
import NumEntries from "./components/num-entries";
import SearchForm from "./components/search-form";
import PasszeroApiV3, {IKeysDatabase, IUser} from "../common-modules/passzero-api-v3";
import { decryptEntryV5WithKeysDatabase } from "../common-modules/crypto-utils";
import { CryptoWorkerRcvMessage, WEBWORKER_MSG_SOURCE } from "../common-modules/message";

// instead of importing include it using a reference (since it's not a module)
// similarly for LogoutTimer variable
/// <reference path="../common/logoutTimer.ts" />

interface IAppProps {}

interface IService {
    name: string;
    link: string;
    has_two_factor: boolean;
}

interface IAppState {
    entries: IEntry[];
    entriesLoaded: boolean;
    searchString: string;
    masterPassword: string;
    servicesLoaded: boolean;
    services: IService[];
    loadingErrorMsg: string | null;
    /**
     * Details about the user
     */
    user: IUser | null;
    /**
     * Decrypted keys database (if available)
     * Can be null even if it is loaded (for example local decryption failed)
     */
    keysDB: IKeysDatabase | null;
    // true iff the keys database has been loaded from server
    isKeysDBLoaded: boolean;
}

class App extends Component<IAppProps, IAppState> {
    logoutTimer: LogoutTimer;
    pzApi: PasszeroApiV3;
    worker: Worker;

    constructor(props: IAppProps) {
        super(props);

        this.logoutTimer = new LogoutTimer();
        this.pzApi = new PasszeroApiV3();

        this.state = {
            // entries, eventually loaded from the server
            entries: [],
            // whether the entries have been loaded from the server
            entriesLoaded: false,
            // search string entered by the user
            searchString: "",
            // filled in componentDidMount
            masterPassword: "",
            services: [],
            servicesLoaded: false,
            user: null,
            keysDB: null,
            isKeysDBLoaded: false,

            // error msg if entries fail to load
            loadingErrorMsg: null,
        };

        this.findEntryIndex = this.findEntryIndex.bind(this);
        this.searchFilterEntries = this.searchFilterEntries.bind(this);
        this.handleDecrypt = this.handleDecrypt.bind(this);
        this.handleDelete = this.handleDelete.bind(this);
        this.handleSearch = this.handleSearch.bind(this);
        this.handleGetUser = this.handleGetUser.bind(this);
        this.handleWorkerMessage = this.handleWorkerMessage.bind(this);
        this.addServicesToEntries = this.addServicesToEntries.bind(this);

        // create worker thread
        this.worker = new window.Worker('/js/dist/web-worker.bundle.js');
        // prepare to receive a message from worker
        this.worker.onmessage = this.handleWorkerMessage;
    }

    componentDidMount() {
        // start the logout timer
        this.logoutTimer.startLogoutTimer();

        // try to read the access token from context.

        const masterPassword = (document.getElementById("master_password") as HTMLInputElement).value;
        this.setState({
            masterPassword: masterPassword,
        });

        this.pzApi.getServices()
            .then((response) => {
                console.log("services:");
                console.log(response);
                this.setState({
                    services: response.services,
                    servicesLoaded: true,
                }, this.addServicesToEntries);
            }).catch((err) => {
                console.error("Failed to load services from server");
                console.error(err);
            });

        this.pzApi.getEncryptedEntries()
            .then((entries: IEncryptedEntry[]) => {
                console.log("entries loaded from server");
                this.setState({
                    entries: entries,
                    entriesLoaded: true,
                }, this.addServicesToEntries);
            }).catch((err: Error) => {
                console.error("Failed to load entries from server");
                console.error(err);
                this.setState({
                    loadingErrorMsg: err.message
                });
            }).then(() => {
                return this.pzApi.getCurrentUser();
            }).then((user: IUser) => {
                this.handleGetUser(user);
            });
    }

    async handleWorkerMessage(event: MessageEvent) {
        console.debug('Received message in main thread from worker');
        console.debug(event.data);
        if (event.data.source && event.data.source === WEBWORKER_MSG_SOURCE && event.data.method) {
            const message = event.data as CryptoWorkerRcvMessage;
            switch (message.method) {
                case 'decryptEncryptionKeysDatabase': {
                    this.setState({
                        keysDB: message.data.keysDB as IKeysDatabase,
                    });
                    break;
                }
                default: {
                    console.error(`Got invalid method in main thread: ${message.method}`);
                    break;
                }
            }
        } else {
            console.warn(`Received message in main thread from unknown source ${event.data.source}`);
        }
    }

    /**
     * Once the current user is fetched from the backend, try to decrypt encryption keys
     */
    async handleGetUser(user: IUser) {
        if (user.encryption_keys) {
            this.worker.postMessage({
                source: 'entries-bundle',
                method: 'decryptEncryptionKeysDatabase',
                data: {
                    encryption_keys: user.encryption_keys,
                    master_password: this.state.masterPassword,
                }
            } as CryptoWorkerRcvMessage);
        }
        // NOTE: some users may have a null keysDB
        // we don't want to prevent encryption if that is the case
        this.setState({
            user: user,
            isKeysDBLoaded: true,
        });
    }

    addServicesToEntries(): void {
        if (!this.state.servicesLoaded || !this.state.entriesLoaded) {
            return;
        }

        // create the services map
        const serviceMap = {};
        let changed = false;

        for (const service of this.state.services) {
            serviceMap[service.name.toLowerCase()] = service.link;
        }

        for (const entry of this.state.entries) {
            if (serviceMap.hasOwnProperty(entry.account.toLowerCase())) {
                entry.service_link = serviceMap[entry.account.toLowerCase()];
                changed = true;
            }
        }

        if (changed) {
            this.setState({
                entries: this.state.entries,
            }, () => {
                console.log("service links added to entries");
            });
        } else {
            console.log("no service links added to entries");
        }
    }

    /**
     * find the index of the entry given its ID within `this.state.entries`
     */
    findEntryIndex(entryId: number): (number | null) {
        for (let i = 0; i < this.state.entries.length; i++) {
            if (this.state.entries[i].id === entryId) {
                return i;
            }
        }
        return null;
    }

    handleDelete(entryId: number): void {
        const entryIndex = this.findEntryIndex(entryId);
        if (entryIndex === null) {
            console.error(`Entry with ID ${entryId} not found`);
            return;
        }

        console.log("Deleting entry...");
        this.pzApi.deleteEntry(entryId, this.state.masterPassword)
            .then(() => {
                window.location.reload();
            });
    }

    /**
     * Decrypt an individual entry. Where possible, decrypt that entry on the client-side.
     */
    async handleDecrypt(entryId: number): Promise<void> {
        const entryIndex = this.findEntryIndex(entryId);
        if (entryIndex === null) {
            console.error(`Entry with ID ${entryId} not found`);
            return;
        }

        // reset the logout timer
        this.logoutTimer.resetLogoutTimer();

        const entry = this.state.entries[entryIndex];
        if (!entry.is_encrypted) {
            console.warn(`Entry with ID ${entryId} is already decrypted, nothing to do`);
            return;
        }

        let decryptedEntry = null as (IDecryptedEntry | null);
        if ((entry as IEncryptedEntry).version === 5 && this.state.keysDB && entry.id.toString() in this.state.keysDB.entry_keys) {
            console.debug('decrypting this entry (v5) on the client-side...');
            decryptedEntry = await decryptEntryV5WithKeysDatabase(
                entry as IEncryptedEntry,
                this.state.keysDB,
            );
        } else {
            const start = new Date().valueOf();
            decryptedEntry = await this.pzApi.decryptEntry(entryId, this.state.masterPassword);
            decryptedEntry.is_encrypted = false;
            // TODO this is a hack for the sole purpose of using the fake data
            decryptedEntry.account = entry.account;
            decryptedEntry.id = entry.id;
            // this allows us to not rerun the service map stuff again
            decryptedEntry.service_link = entry.service_link;
            const end = new Date().valueOf();
            console.log(`Took ${end - start}ms to decrypt on the server`);
        }

        // replace the encrypted entry with the decrypted entry
        const newEntries = this.state.entries;
        newEntries.splice(entryIndex, 1, decryptedEntry);
        // force state reload
        this.setState({
            entries: newEntries
        });
    }

    handleSearch(searchString: string): void {
        this.setState({
            searchString: searchString
        });
    }

    /**
     * Return true iff this entry can be shown
     * Case-insensitive matching along account and username
     * @param {IEntry} entry
     * @returns {boolean}
     */
    searchFilterEntries(entry: IEntry): boolean {
        if (this.state.searchString === null || this.state.searchString === "") {
            // all entries are fine under an empty search string
            return true;
        }

        const q = this.state.searchString.toLowerCase();

        // insensitive case matching on account name
        if (entry.account.toLowerCase().indexOf(q) !== -1) {
            return true;
        }

        // insensitive case matching on username (dec only)
        if (!entry.is_encrypted && (entry as IDecryptedEntry).username.toLowerCase().indexOf(q) !== -1) {
            return true;
        }

        return false;
    }

    render() {
        const filteredEntries = this.state.entries.filter(this.searchFilterEntries);
        // list of Entries components
        const entries = [];
        let entry = null;
        for (let i = 0; i < filteredEntries.length; i++) {
            if (filteredEntries[i].is_encrypted) {
                entry = (<EncryptedEntry
                    entry={ (filteredEntries[i] as IEncryptedEntry) }
                    key={ filteredEntries[i].id }
                    onDecrypt={ this.handleDecrypt }
                    onDelete={ this.handleDelete } />);
            } else {
                entry = (<DecryptedEntry
                    entry={ (filteredEntries[i] as IDecryptedEntry) }
                    key={ filteredEntries[i].id }
                    onDelete={ this.handleDelete } />);
            }
            entries.push(entry);
        }

        if (this.state.loadingErrorMsg) {
            return (<div className="alert alert-danger">
                <strong>Error!</strong>&nbsp;{ this.state.loadingErrorMsg }
            </div>);
        } else {
            return (
                <div id="inner-root">
                    {/* this is just a placeholder for now */}
                    <nav></nav>
                    <main className="container">
                        <div className="inner-container">
                            <NumEntries
                                entriesLoaded={this.state.entriesLoaded}
                                numEntries={this.state.entries.length} />
                            {(this.state.entriesLoaded && this.state.entries.length > 0) ?
                                <SearchForm onSearch={this.handleSearch} /> :
                                null}
                            <div id="entry-container">
                                {entries}
                            </div>
                        </div>
                    </main>
                </div>
            );
        }
    }
}

export default App;
