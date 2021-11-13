import { Component } from "react";
import * as React from "react";
import { chunk } from "lodash";
import PasszeroApiV3, {IUser, IKeysDatabase} from "../common-modules/passzero-api-v3";
import DecryptedLink from "./components/decrypted-link";
import EncryptedLink from "./components/encrypted-link";
import {IDecryptedLink, IEncryptedLink, ILink} from "../common-modules/links";
import SearchForm from "../entries-bundle/components/search-form";
import { decryptEncryptionKeysDatabase, decryptLinkWithKeysDB } from "../common-modules/crypto-utils";

// instead of importing, include it using a reference (since it's not a module)
// similarly for LogoutTimer variable
/// <reference path="../common/logoutTimer.ts" />

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
     */
    keysDB: IKeysDatabase | null;
}

/**
 * Batch size used to decrypt links
 */
const DECRYPTION_BATCH_SIZE = 10;
/**
 * Time in milliseconds to delay decrypting the keys database
 */
const DECRYPT_KEYS_DB_DELAY = 750;

class App extends Component<IProps, IState> {
    logoutTimer: LogoutTimer;
    pzApi: PasszeroApiV3;

    constructor(props: any) {
        super(props);

        this.state = {
            links: [],
            searchString: "",
            linksLoaded: false,
            masterPassword: null,
            isDecrypting: false,
            isAllDecrypted: false,
            user: null,
            keysDB: null,
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
    }

    componentDidMount() {
        this.logoutTimer.startLogoutTimer();

        const masterPassword = (document.getElementById("master_password") as HTMLInputElement).value;
        this.setState({
            masterPassword: masterPassword,
        });

        console.debug("Fetching links...");
        // fetch all the encrypted links
        this.pzApi.getEncryptedLinks()
            .then((response) => {
                console.debug("links:");
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
                console.error("Failed to get links");
                console.error(err);
                if (err.name === "UnauthorizedError") {
                    window.location.href = "/login";
                } else {
                    console.debug("different type of error: " + err.name);
                }
            }).then(() => {
                return this.pzApi.getCurrentUser();
            }).then((user: IUser) => {
                // run with a delay so it doesn't interfere with rendering
                window.setTimeout(() => {
                    this.handleGetUser(user);
                }, DECRYPT_KEYS_DB_DELAY);
            });
    }

    /**
     * Once the current user is fetched from the backend, try to decrypt encryption keys
     */
    async handleGetUser(user: IUser) {
        let decEncryptionKeys = null;
        if (user.encryption_keys) {
            decEncryptionKeys = await decryptEncryptionKeysDatabase(
                user.encryption_keys,
                this.state.masterPassword
            );
        }
        this.setState({
            user: user,
            keysDB: decEncryptionKeys,
        });
    }

    renderLoading() {
        return <div>Loading links...</div>;
    }

    renderEmpty() {
        return (
            <div>
                You don't have any saved links yet. Create some <a href="/links/new">here</a>.
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
                    console.debug("Got decrypted link from server");
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
            this.state.masterPassword
        ) as IDecryptedLink[];

        // massage data format
        decLinks.forEach(link => {
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
     */
    handleDecryptAll(): void {
        // reset the logout timer when button is pressed
        this.logoutTimer.resetLogoutTimer();

        this.setState({
            // don't allow the user to press the decrypt button while we're decrypting
            isDecrypting: true,
            isAllDecrypted: false,
        }, async () => {
            // this is just used for metrics collection
            const startTime = (new Date()).valueOf();
            const encLinkIds = this.state.links
                .filter(link => link.is_encrypted)
                .map(link => link.id);

            // map from link ID to its index
            const indexMap = {}
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
            }
            console.log(`Split the IDs into ${localIds.length} local links and ${remoteIds.length} remote links`);

            // split the IDs into chunks of DECRYPTION_BATCH_SIZE
            const chunks = chunk(remoteIds, DECRYPTION_BATCH_SIZE);
            // keep track of how many have been decrypted
            let numDecrypted = 0;

            chunks.map(async (idsChunk: number[]) => {
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

            localIds.map(async (linkId: number) => {
                // we know that this ID exists in the local keys DB
                const idx = indexMap[linkId];
                const link = this.state.links[idx] as IEncryptedLink;
                const decLink = await decryptLinkWithKeysDB(link, this.state.keysDB);
                numDecrypted += 1;
                const isDecrypting = numDecrypted < encLinkIds.length;

                const newLinks = this.state.links;
                newLinks.splice(idx, 1, decLink);

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

    /**
     * Decrypt all links by hitting the decryption API for each link one at a time.
     * This method will only show the links (update the state) when *all* links have been decrypted
     * This is also pretty hard for the server to handle as it creates many parallel requests,
     * especially if the server is pre-HTTP-2
     */
    handleDecryptAllOld(): void {
        // reset the logout timer when button is pressed
        this.logoutTimer.resetLogoutTimer();

        // step 1 - disable the button
        if (this.state.isDecrypting) {
            // do nothing while there is a decryption operation already in progress
            return;
        }

        this.setState({
            isDecrypting: true,
        }, async () => {
            const start = new Date();
            const newLinks = {};
            const promises = [];

            for (let i = 0; i < this.state.links.length; i++) {
                const link = this.state.links[i];
                if (link.is_encrypted) {
                    // send out all requests to decrypt individual items, but do not wait on responses here
                    promises.push(
                        this.pzApi.decryptLink(link.id, this.state.masterPassword)
                            .then((response) => {
                                console.debug(`Got decrypted link from server: ${response.service_name}`);
                                // console.debug(response);
                                const decLink = response as IDecryptedLink;
                                decLink.is_encrypted = false;
                                newLinks[i] = decLink;
                            })
                    );
                }
            }
            // wait for all asynchronous decryption requests to come back
            await Promise.all(promises);
            console.debug(`all ${promises.length} links decrypted`);

            const newArr = this.state.links;
            for (const linkIndex in newLinks) {
                newArr.splice(Number.parseInt(linkIndex, 10), 1, newLinks[linkIndex]);
            }

            const end = new Date();
            console.debug(`Operation took ${end.valueOf() - start.valueOf()} ms`);

            this.setState({
                links: newArr,
                isDecrypting: false,
            });
        });
    }

    handleDecrypt(linkIndex: number): void {
        if (this.state.isDecrypting) {
            // do nothing while there is a decryption operation already in progress
            return;
        }
        this.setState({
            isDecrypting: true
        }, async () => {
            const link = this.state.links[linkIndex];
            let decLink = null;
            if (this.state.keysDB && link.id.toString() in this.state.keysDB.link_keys) {
                console.debug(`Locally decrypting link with ID ${link.id}...`)
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
                if (this.state.isAllDecrypted && this.state.searchString !== "") {
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
            <div>
                <div className="links-control-panel">
                    <a href="/links/new" className="new-link-btn control-panel-btn btn btn-lg btn-success">
                        Create New Link
                    </a>
                    { this.state.isAllDecrypted ? null : <button type="button"
                        className="decrypt-all-btn control-panel-btn btn btn-lg btn-info"
                        disabled={ this.state.isDecrypting || !this.state.keysDB }
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

export default App;
