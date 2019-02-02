/**
 * This is the top-level component for the PassZero application
 */

import { Component } from 'react';
import * as React from 'react';
import EncryptedEntry from './components/encrypted-entry';
import DecryptedEntry from './components/decrypted-entry';
import NumEntries from './components/num-entries';
import SearchForm from './components/search-form';
import {IEntry, IDecryptedEntry, IEncryptedEntry} from './components/entries';

import PasszeroApiV3 from '../common-modules/passzero-api-v3';

// instead of importing include it using a reference (since it's not a module)
// similarly for LogoutTimer variable
/// <reference path="../common/logoutTimer.ts" />

interface IAppProps {}

interface IAppState {
    entries: IEntry[];
    entriesLoaded: boolean;
    searchString: string;
    masterPassword: string;
    servicesLoaded: boolean;
    services: IService[];
}

class App extends Component<IAppProps, IAppState> {
    logoutTimer: LogoutTimer;
    pzApi: PasszeroApiV3;

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
            searchString: '',
            // filled in componentDidMount
            masterPassword: '',
            services: [],
            servicesLoaded: false,
        };

        this.findEntryIndex = this.findEntryIndex.bind(this);
        this.searchFilterEntries = this.searchFilterEntries.bind(this);
        this.handleDecrypt = this.handleDecrypt.bind(this);
        this.handleDelete = this.handleDelete.bind(this);
        this.handleSearch = this.handleSearch.bind(this);

        this.addServicesToEntries = this.addServicesToEntries.bind(this);
    }

    componentDidMount() {
        // start the logout timer
        this.logoutTimer.startLogoutTimer();

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
                console.error(err)
            });

        this.pzApi.getEncryptedEntries()
            .then((entries: IEncryptedEntry[]) => {
                console.log("entries loaded from server");
                this.setState({
                    entries: entries,
                    entriesLoaded: true,
                }, this.addServicesToEntries);
            }).catch((err) => {
                console.error("Failed to load entries from server");
                console.error(err);
            });
    }

    addServicesToEntries(): void {
        if(!this.state.servicesLoaded || !this.state.entriesLoaded) {
            return;
        }

        // create the services map
        const serviceMap = {};
        let changed = false;

        for(let service of this.state.services) {
            serviceMap[service.name.toLowerCase()] = service.link;
        }

        for(let entry of this.state.entries) {
            if(serviceMap.hasOwnProperty(entry.account.toLowerCase())) {
                entry.service_link = serviceMap[entry.account.toLowerCase()];
                changed = true;
            }
        }

        if(changed) {
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
        for(let i = 0; i < this.state.entries.length; i++) {
            if(this.state.entries[i].id === entryId) {
                return i;
            }
        }
        return null;
    }

    handleDelete(entryId: number): void {
        const entryIndex = this.findEntryIndex(entryId);
        if(entryIndex === null) {
            console.error(`Entry with ID ${entryId} not found`);
            return;
        }

        console.log('Deleting entry...');
        this.pzApi.deleteEntry(entryId)
            .then(() => {
                window.location.reload();
            });
    }

    handleDecrypt(entryId: number): void {
        const entryIndex = this.findEntryIndex(entryId);
        if(entryIndex === null) {
            console.error(`Entry with ID ${entryId} not found`);
            return;
        }
        const entry = this.state.entries[entryIndex];

        this.pzApi.decryptEntry(entryId, this.state.masterPassword)
            .then((decryptedEntry: IDecryptedEntry) => {
                decryptedEntry.is_encrypted = false;
                // TODO this is a hack for the sole purpose of using the fake data
                decryptedEntry.account = entry.account;
                decryptedEntry.id = entry.id;
                // this allows us to not rerun the service map stuff again
                decryptedEntry.service_link = entry.service_link;

                // replace the encrypted entry with the decrypted entry
                let newEntries = this.state.entries;
                newEntries.splice(entryIndex, 1, decryptedEntry);
                // force state reload
                this.setState({
                    entries: newEntries
                });
            })
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
        if(this.state.searchString === null || this.state.searchString === '') {
            // all entries are fine under an empty search string
            return true;
        }

        let q = this.state.searchString.toLowerCase();

        // insensitive case matching on account name
        if(entry.account.toLowerCase().indexOf(q) !== -1) {
            return true;
        }

        // insensitive case matching on username (dec only)
        if(!entry.is_encrypted && (entry as IDecryptedEntry).username.toLowerCase().indexOf(q) !== -1) {
            return true;
        }

        return false;
    }

    render() {
        const filteredEntries = this.state.entries.filter(this.searchFilterEntries);
        // list of Entries components
        let entries = [], entry = null;
        for(let i = 0; i < filteredEntries.length; i++) {
            if(filteredEntries[i].is_encrypted) {
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

        return (
            <div id='inner-root'>
                {/* this is just a placeholder for now */}
                <nav></nav>
                <main className='container'>
                    <div className='inner-container'>
                        <NumEntries
                            entriesLoaded={this.state.entriesLoaded}
                            numEntries={this.state.entries.length} />
                        {(this.state.entriesLoaded && this.state.entries.length > 0) ?
                            <SearchForm onSearch={this.handleSearch} /> :
                            null}
                        <div id='entry-container'>
                            {entries}
                        </div>
                    </div>
                </main>
            </div>
        );
    }
}

export default App;
