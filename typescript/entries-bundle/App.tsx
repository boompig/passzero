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

// instead of importing passzero_api, include it using a reference (since it's not a module)
// introduces pzAPI variable
/// <reference path="../common/passzero_api.ts" />
// similarly for LogoutTimer variable
/// <reference path="../common/logoutTimer.ts" />

interface IAppProps {}

interface IAppState {
    entries: IEntry[];
    entriesLoaded: boolean;
    searchString: string;
}

class App extends Component<IAppProps, IAppState> {
	logoutTimer: LogoutTimer;

    constructor(props: IAppProps) {
		super(props);

		this.logoutTimer = new LogoutTimer();

        this.state = {
            // entries, eventually loaded from the server
            entries: [],
            // whether the entries have been loaded from the server
            entriesLoaded: false,
            // search string entered by the user
            searchString: '',
        };

        this.findEntryIndex = this.findEntryIndex.bind(this);
        this.searchFilterEntries = this.searchFilterEntries.bind(this);
        this.handleDecrypt = this.handleDecrypt.bind(this);
        this.handleDelete = this.handleDelete.bind(this);
        this.handleSearch = this.handleSearch.bind(this);
    }

    componentDidMount() {
		// start the logout timer
		this.logoutTimer.startLogoutTimer();

        pzAPI.getEntriesV2()
            .then((entries: IEncryptedEntry[]) => {
                this.setState({
                    entries: entries,
                    entriesLoaded: true,
                });
            });

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
        pzAPI.deleteEntry(entryId)
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

        pzAPI.decryptEntry(entryId)
            .then((decryptedEntry: IDecryptedEntry) => {
                decryptedEntry.is_encrypted = false;
                // TODO this is a hack for the sole purpose of using the fake data
                decryptedEntry.account = entry.account;
                decryptedEntry.id = entry.id;

                // replace the encrypted entry with the decrypted entry
                let newEntries = this.state.entries;
                newEntries.splice(entryIndex, 1, decryptedEntry);

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
