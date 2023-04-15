import { Component } from 'react';
import * as React from 'react';
import { chunk } from 'lodash';

import PasszeroApiV3, { IUser, IKeysDatabase } from '../common-modules/passzero-api-v3';
import DecryptedLink from './components/decrypted-link';
import EncryptedLink from './components/encrypted-link';
import { IDecryptedLink, IEncryptedLink, ILink } from '../common-modules/links';
import SearchForm from '../entries-bundle/components/search-form';
import { decryptLinkWithKeysDB } from '../common-modules/crypto-utils';
import { CryptoWorkerRcvMessage, WEBWORKER_MSG_SOURCE } from '../common-modules/message';
import LogoutTimer from '../common-modules/logoutTimer';
import { clientSideLogout } from '../common-modules/client-side-utils';
import { LoggedInLayout } from '../components/LoggedInLayout';
import { readSavedMasterPassword } from '../providers/master-password-provider';

import './links.css';

interface IProps {}

interface IState {
    links: ILink[];
    // local search on decrypted entries
    searchString: string;
    // true iff the encrypted links have been loaded from the server
    linksLoaded: boolean;
    // filled on componentDidMount
    masterPassword: (string | null);
    // true iff currently decrypting something
    isDecrypting: boolean;
    // true iff all links have been decrypted
    isAllDecrypted: boolean;
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

/**
 * Batch size used to decrypt links
 */
const DECRYPTION_BATCH_SIZE = 10;

class LinksAppInner extends Component<IProps, IState> {
    logoutTimer: LogoutTimer;
    pzApi: PasszeroApiV3;
    worker: Worker;

    constructor(props: any) {
        super(props);

        this.state = {
            links: [],
            searchString: '',
            linksLoaded: false,
            masterPassword: null,
            isDecrypting: false,
            isAllDecrypted: false,
            user: null,
            keysDB: null,
            isKeysDBLoaded: false,
        };

        this.logoutTimer = new LogoutTimer();
        this.pzApi = new PasszeroApiV3();

        // javascript is terrible
        this.handleDecrypt = this.handleDecrypt.bind(this);
        this.handleDelete = this.handleDelete.bind(this);
        this.renderLoading = this.renderLoading.bind(this);
        this.renderEmpty = this.renderEmpty.bind(this);
        this.renderLinks = this.renderLinks.bind(this);
        this.handleDecryptAll = this.handleDecryptAll.bind(this);
        this.handleSearch = this.handleSearch.bind(this);
        this.decryptList = this.decryptList.bind(this);
        this.handleGetUser = this.handleGetUser.bind(this);
        this.handleWorkerMessage = this.handleWorkerMessage.bind(this);
        this.resetTimer = this.resetTimer.bind(this);

        // create worker thread
        this.worker = new window.Worker('/js/dist/web-worker.bundle.js');
        // prepare to receive a message from worker
        this.worker.onmessage = this.handleWorkerMessage;
    }

    componentDidMount() {
        this.logoutTimer.startLogoutTimer();

        const masterPassword = readSavedMasterPassword();
        if (!masterPassword) {
            clientSideLogout();
            throw new Error('failed to load master password from storage');
        }

        this.setState({
            masterPassword: masterPassword,
        });

        console.debug('Fetching links...');
        // fetch all the encrypted links
        this.pzApi.getEncryptedLinks()
            .then((response) => {
                console.debug('links:');
                console.debug(response);

                // alter each link to set encrypted = true
                for (const link of response) {
                    link.is_encrypted = true;
                }

                this.setState({
                    links: response,
                    linksLoaded: true,
                });
            })
            .catch((err) => {
                console.error('Failed to get links');
                console.error(err);
                if (err.name === 'UnauthorizedError') {
                    // likely the token has expired
                    clientSideLogout();
                } else {
                    console.debug('different type of error: ' + err.name);
                }
            }).then(() => {
                return this.pzApi.getCurrentUser();
            }).then((user: IUser) => {
                this.handleGetUser(user);
            });
    }

    resetTimer() {
        this.logoutTimer.resetLogoutTimer();
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
        // NOTE: some users may not have a keysDB associated with their user
        // in that case, we don't want to prevent decryption
        if (user.encryption_keys) {
            this.worker.postMessage({
                source: 'entries-bundle',
                method: 'decryptEncryptionKeysDatabase',
                data: {
                    encryption_keys: user.encryption_keys,
                    master_password: this.state.masterPassword,
                },
            } as CryptoWorkerRcvMessage);
        }
        this.setState({
            user: user,
            isKeysDBLoaded: true,
        });
    }

    renderLoading() {
        return <div>Loading links...</div>;
    }

    renderEmpty() {
        return (
            <div>
                You don&apos;t have any saved links yet. Create some <a href="/links/new">here</a>.
            </div>
        );
    }

    handleSearch(searchString: string): void {
        this.setState({
            searchString: searchString,
        });
    }

    handleDelete(linkIndex: number): void {
        const ok = confirm('Are you sure you want to delete this link?');
        if (ok) {
            const link = this.state.links[linkIndex];
            console.debug(`Deleting link with ID ${link.id}...`);
            this.pzApi.deleteLink(link.id, this.state.masterPassword)
                .then((response) => {
                    console.debug('Got decrypted link from server');
                    const newLinks = this.state.links;
                    newLinks.splice(linkIndex, 1);
                    // force state reload
                    this.setState({
                        links: newLinks,
                    });
                });
        }
    }

    /**
     * Decrypt all links with the given IDs
     */
    async decryptList(linkIds: number[]): Promise<IDecryptedLink[]> {
        const startTime = (new Date()).valueOf();

        const decLinks = await this.pzApi.decryptLinks(
            linkIds,
            this.state.masterPassword,
        ) as IDecryptedLink[];

        // massage data format
        decLinks.forEach((link) => {
            link.is_encrypted = false;
        });

        const endTime = (new Date()).valueOf();
        console.debug(`All ${linkIds.length} decrypted. Took ${endTime - startTime} ms`);

        return decLinks;
    }

    /**
     * This is the newer and recommended implementation for decrypting all the links
     * This method decrypts the links in batches of DECRYPTION_BATCH_SIZE using the batch-decryption API for links
     * The view (state) is updated every time a batch is returned from the server
     * The down-side of this method is it can keep the server occupied for a significant amount of time as a batch takes a while to decrypt
     *
     * This method will decrypt links locally if it can
     * If the keys database fails to load or decrypt, decryption will continue as normal on the server
     */
    handleDecryptAll(): void {
        // reset the logout timer when button is pressed
        this.resetTimer();

        this.setState({
            // don't allow the user to press the decrypt button while we're decrypting
            isDecrypting: true,
            isAllDecrypted: false,
        }, async () => {
            // this is just used for metrics collection
            const startTime = (new Date()).valueOf();
            const encLinkIds = this.state.links
                .filter((link) => link.is_encrypted)
                .map((link) => link.id);

            // map from link ID to its index
            const indexMap = {};
            for (let i = 0; i < this.state.links.length; i++) {
                indexMap[this.state.links[i].id] = i;
            }

            const localIds = [];
            const remoteIds = [];
            const numToDecrypt = encLinkIds.length;
            // some of these link IDs are in the local keys database
            if (this.state.keysDB) {
                encLinkIds.forEach((id: number) => {
                    if (id.toString() in this.state.keysDB.link_keys) {
                        localIds.push(id);
                    } else {
                        remoteIds.push(id);
                    }
                });
            } else {
                remoteIds.push(...encLinkIds);
            }

            console.log(`Split the IDs into ${localIds.length} local links and ${remoteIds.length} remote links`);

            // split the IDs into chunks of DECRYPTION_BATCH_SIZE for remote decryption
            const remoteChunks = chunk(remoteIds, DECRYPTION_BATCH_SIZE);
            // keep track of how many have been decrypted
            let numDecrypted = 0;

            remoteChunks.map(async (idsChunk: number[]) => {
                // decrypt this chunk
                const decLinks = await this.decryptList(idsChunk);
                // make a copy - don't modify original
                const newLinks = [...this.state.links];
                // replace each element at the correct index
                decLinks.forEach((decLink: IDecryptedLink) => {
                    const i = indexMap[decLink.id];
                    newLinks[i] = decLink;
                });

                numDecrypted += decLinks.length;
                const isDecrypting = numDecrypted < encLinkIds.length;

                const endTime = (new Date()).valueOf();
                console.debug(`Completed decryption of ${numDecrypted}/${encLinkIds.length} links. Took ${endTime - startTime} ms from start.`);

                // update the links with
                this.setState({
                    links: newLinks,
                    isDecrypting: isDecrypting,
                });

                if (numDecrypted === numToDecrypt) {
                    this.setState({
                        isAllDecrypted: true,
                    });
                }
            });

            localIds.forEach(async (linkId: number) => {
                // we know that this ID exists in the local keys DB
                const idx = indexMap[linkId];
                const link = this.state.links[idx] as IEncryptedLink;
                const decLink = await decryptLinkWithKeysDB(link, this.state.keysDB);
                numDecrypted += 1;
                const isDecrypting = numDecrypted < encLinkIds.length;

                const newLinks = this.state.links;
                newLinks.splice(idx, 1, decLink);

                // note that this setState function is called on EVERY ITERATION
                this.setState({
                    links: newLinks,
                    isDecrypting: isDecrypting,
                });

                if (numDecrypted === numToDecrypt) {
                    this.setState({
                        isAllDecrypted: true,
                    });
                }
            });
        });
    }

    handleDecrypt(linkIndex: number): void {
        if (this.state.isDecrypting) {
            // do nothing while there is a decryption operation already in progress
            return;
        }
        this.setState({
            isDecrypting: true,
        }, async () => {
            const link = this.state.links[linkIndex];
            let decLink = null;
            if (this.state.keysDB && link.id.toString() in this.state.keysDB.link_keys) {
                console.debug(`Locally decrypting link with ID ${link.id}...`);
                decLink = await decryptLinkWithKeysDB(link as IEncryptedLink, this.state.keysDB);
                console.debug('Successfully decrypted link locally');
            } else {
                console.debug(`Remotely decrypting link with ID ${link.id}...`);
                decLink = await this.pzApi.decryptLink(link.id, this.state.masterPassword);
                console.debug('Got decrypted link from server');
            }
            if (decLink) {
                // replace encrypted link with new link
                const newLinks = this.state.links;
                newLinks.splice(linkIndex, 1, decLink);
                // force state reload
                this.setState({
                    links: newLinks,
                    isDecrypting: false,
                });
            }
        });
    }

    /**
     * This method is called when links are loaded and this.state.links is non-empty
     */
    renderLinks() {
        const linkElems = [];
        const ss = this.state.searchString.toLowerCase();
        for (let i = 0; i < this.state.links.length; i++) {
            const link = this.state.links[i];
            let linkElem = null;
            if (link.is_encrypted) {
                linkElem = <EncryptedLink
                    link={ (link as IEncryptedLink) }
                    key={ `enc-link-${link.id}` }
                    index={ i }
                    isDecrypting={ this.state.isDecrypting }
                    onDecrypt={ this.handleDecrypt }
                    onDelete={ this.handleDelete } />;
            } else {
                let isFiltered = false;
                if (this.state.isAllDecrypted && this.state.searchString !== '') {
                    const name = (link as IDecryptedLink).service_name.toLowerCase();
                    const href = (link as IDecryptedLink).link.toLowerCase();
                    if (!name.includes(ss) && !href.includes(ss)) {
                        isFiltered = true;
                    }
                }
                if (isFiltered) {
                    // console.debug(`Link with service name ${(link as IDecryptedLink).service_name} is filtered`);
                    continue;
                }


                linkElem = <DecryptedLink link={ (link as IDecryptedLink) } key={ `dec-link-${link.id}` } index={ i }
                    onDelete={ this.handleDelete }/>;
            }
            linkElems.push(linkElem);
        }

        return (
            <div onScroll={this.resetTimer}>
                <div className="links-control-panel">
                    <a href="/links/new" className="new-link-btn control-panel-btn btn btn-lg btn-success">
                        Create New Link
                    </a>
                    { this.state.isAllDecrypted ? null : <button type="button"
                        className="decrypt-all-btn control-panel-btn btn btn-lg btn-info"
                        disabled={ this.state.isDecrypting || !this.state.isKeysDBLoaded }
                        onClick={ this.handleDecryptAll }>
                        Decrypt All
                    </button> }
                </div>
                {(this.state.linksLoaded && this.state.links.length > 0 && this.state.isAllDecrypted) ?
                    <SearchForm onSearch={this.handleSearch} /> :
                    null}
                <div className="link-container">
                    { linkElems }
                </div>
            </div>
        );
    }

    render() {
        if (!this.state.linksLoaded) {
            return this.renderLoading();
        } else if (this.state.linksLoaded && this.state.links.length === 0) {
            return this.renderEmpty();
        } else {
            return this.renderLinks();
        }
    }
}

const LinksApp = () => {
    return <LoggedInLayout>
        <LinksAppInner />
    </LoggedInLayout>;
};

export default LinksApp;
