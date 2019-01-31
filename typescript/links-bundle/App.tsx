import { Component } from 'react';
import * as React from 'react';
import DecryptedLink from './components/decrypted-link';
import EncryptedLink from './components/encrypted-link';
import {IEncryptedLink, IDecryptedLink, ILink} from './components/links';

// instead of importing passzero_api, include it using a reference (since it's not a module)
// introduces pzAPI variable
/// <reference path='../common/passzero_api.ts' />
// similarly for LogoutTimer variable
/// <reference path='../common/logoutTimer.ts' />

interface IProps {}

interface IState {
    links: (ILink)[];
    // true iff the encrypted links have been loaded from the server
    linksLoaded: boolean;
    // filled in after the first API call
    apiToken: (string | null);
    // filled on componentDidMount
    masterPassword: (string | null);
}

class App extends Component<IProps, IState> {
    logoutTimer: LogoutTimer;

    constructor(props: any) {
        super(props);

        this.state = {
            links: [],
            linksLoaded: false,
            apiToken: null,
            masterPassword: null,
        }

        this.logoutTimer = new LogoutTimer();

        // javascript is terrible
        this.handleDecrypt = this.handleDecrypt.bind(this);
        this.handleDelete = this.handleDelete.bind(this);
        this.renderLoading = this.renderLoading.bind(this);
        this.renderEmpty = this.renderEmpty.bind(this);
        this.renderLinks = this.renderLinks.bind(this);
    }

    componentDidMount() {
        this.logoutTimer.startLogoutTimer();

        const masterPassword = (document.getElementById('master_password') as HTMLInputElement).value;
        this.setState({
            masterPassword: masterPassword,
        });

        console.log('Fetching links...');
        // fetch all the encrypted links
        pzAPI.getEncryptedLinks()
            .then((response) => {
                console.log('links:');
                console.log(response);

                // alter each link to set encrypted = true
                for(let link of response.links) {
                    link.is_encrypted = true;
                }

                this.setState({
                    links: response.links,
                    apiToken: response.apiToken,
                    linksLoaded: true,
                });
            })
            .catch((err) => {
                console.error('Failed to get links');
                console.error(err);
                if(err.name === 'UnauthorizedError') {
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
                You don't have any saved links yet. Create some <a href='/links/new'>here</a>.
            </div>
        );
    }

    handleDelete(linkIndex: number): void {
        const link = this.state.links[linkIndex];
        console.log(`Deleting link with ID ${link.id}...`);
        pzAPI.deleteLink(link.id, this.state.apiToken)
            .then((response) => {
                console.log("Got decrypted link from server");
                let newLinks = this.state.links;
                newLinks.splice(linkIndex, 1);
                // force state reload
                this.setState({
                    links: newLinks,
                });
            });
    }

    handleDecrypt(linkIndex: number): void {
        const link = this.state.links[linkIndex];
        console.log(`Decrypting link with ID ${link.id}...`);
        pzAPI.decryptLink(link.id, this.state.apiToken, this.state.masterPassword)
            .then((response) => {
                console.log("Got decrypted link from server");
                // console.log(response);
                const decLink = response;
                decLink.is_encrypted = false;
                // replace encrypted link with new link
                let newLinks = this.state.links;
                newLinks.splice(linkIndex, 1, decLink);
                // force state reload
                this.setState({
                    links: newLinks,
                });
            });
    }

    /**
     * This method is called when links are loaded and this.state.links is non-empty
     */
    renderLinks() {
        const linkElems = [];
        for(let i = 0; i < this.state.links.length; i++) {
            let link = this.state.links[i];
            let linkElem = null;
            if(link.is_encrypted) {
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
            <div className='link-container'>
                { linkElems }
            </div>
        );
    }

    render() {
        if(!this.state.linksLoaded) {
            return this.renderLoading();
        } else if(this.state.linksLoaded && this.state.links.length === 0) {
            return this.renderEmpty();
        } else {
            return this.renderLinks();
        }
    }
}

export default App;