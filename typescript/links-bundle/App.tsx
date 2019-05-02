import { Component } from "react";
import * as React from "react";
import PasszeroApiV3 from "../common-modules/passzero-api-v3";
import DecryptedLink from "./components/decrypted-link";
import EncryptedLink from "./components/encrypted-link";
import {IDecryptedLink, IEncryptedLink, ILink} from "./components/links";

// instead of importing, include it using a reference (since it's not a module)
// similarly for LogoutTimer variable
/// <reference path="../common/logoutTimer.ts" />

interface IProps {}

interface IState {
    links: ILink[];
    // true iff the encrypted links have been loaded from the server
    linksLoaded: boolean;
    // filled on componentDidMount
    masterPassword: (string | null);
    // true iff currently decrypting something
    isDecrypting: boolean;
}

class App extends Component<IProps, IState> {
    logoutTimer: LogoutTimer;
    pzApi: PasszeroApiV3;

    constructor(props: any) {
        super(props);

        this.state = {
            links: [],
            linksLoaded: false,
            masterPassword: null,
            isDecrypting: false,
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
    }

    componentDidMount() {
        this.logoutTimer.startLogoutTimer();

        const masterPassword = (document.getElementById("master_password") as HTMLInputElement).value;
        this.setState({
            masterPassword: masterPassword,
        });

        console.log("Fetching links...");
        // fetch all the encrypted links
        this.pzApi.getEncryptedLinks()
            .then((response) => {
                console.log("links:");
                console.log(response);

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
                    console.log("different type of error: " + err.name);
                }
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

    handleDelete(linkIndex: number): void {
        const link = this.state.links[linkIndex];
        console.log(`Deleting link with ID ${link.id}...`);
        this.pzApi.deleteLink(link.id)
            .then((response) => {
                console.log("Got decrypted link from server");
                const newLinks = this.state.links;
                newLinks.splice(linkIndex, 1);
                // force state reload
                this.setState({
                    links: newLinks,
                });
            });
    }

    handleDecryptAll(): void {
        // step 1 - disable the button
        if (this.state.isDecrypting) {
            // do nothing while there is a decryption operation already in progress
            return;
        }

        this.setState({
            isDecrypting: true,
        }, async () => {
            const newLinks = {};
            const promises = [];

            for (let i = 0; i < this.state.links.length; i++) {
                const link = this.state.links[i];
                if (link.is_encrypted) {
                    // send out all requests to decrypt individual items, but do not wait on responses here
                    promises.push(
                        this.pzApi.decryptLink(link.id, this.state.masterPassword)
                            .then((response) => {
                                console.log(`Got decrypted link from server: ${response.service_name}`);
                                // console.log(response);
                                const decLink = response as IDecryptedLink;
                                decLink.is_encrypted = false;
                                newLinks[i] = decLink;
                            })
                    );
                }
            }
            // wait for all asynchronous decryption requests to come back
            await Promise.all(promises);
            console.log("all links decrypted");

            const newArr = this.state.links;
            for (const linkIndex in newLinks) {
                newArr.splice(Number.parseInt(linkIndex, 10), 1, newLinks[linkIndex]);
            }

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
        }, () => {
            const link = this.state.links[linkIndex];
            console.log(`Decrypting link with ID ${link.id}...`);
            this.pzApi.decryptLink(link.id, this.state.masterPassword)
                .then((response) => {
                    console.log("Got decrypted link from server");
                    // console.log(response);
                    const decLink = response;
                    decLink.is_encrypted = false;
                    // replace encrypted link with new link
                    const newLinks = this.state.links;
                    newLinks.splice(linkIndex, 1, decLink);
                    // force state reload
                    this.setState({
                        links: newLinks,
                        isDecrypting: false,
                    });
                });
        });
    }

    /**
     * This method is called when links are loaded and this.state.links is non-empty
     */
    renderLinks() {
        const linkElems = [];
        for (let i = 0; i < this.state.links.length; i++) {
            const link = this.state.links[i];
            let linkElem = null;
            if (link.is_encrypted) {
                linkElem = <EncryptedLink link={ (link as IEncryptedLink) } index={ i }
                    onDecrypt={ this.handleDecrypt }
                    onDelete={ this.handleDelete }/>;
            } else {
                linkElem = <DecryptedLink link={ (link as IDecryptedLink) } index={ i }
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
                    <button type="button"
                        className="decrypt-all-btn control-panel-btn btn btn-lg btn-info"
                        disabled={ this.state.isDecrypting }
                        onClick={ this.handleDecryptAll }>
                        Decrypt All
                    </button>
                </div>
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
