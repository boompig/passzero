import { PureComponent } from 'react';
import * as React from 'react';

import PasszeroApiV3 from '../common-modules/passzero-api-v3';
import LogoutTimer from '../common-modules/logoutTimer';
import { LoggedInLayout } from '../components/LoggedInLayout';
import { clientSideLogout } from '../common-modules/client-side-utils';
import { readSavedMasterPassword } from '../providers/master-password-provider';

import './new-link.css';

interface INewLinkState {
    name: string;
    link: string;
    masterPassword: string;
    linkId: number;
    isNewLink: boolean;
}

/**
 * Represents editing a new or existing link
 */
class NewLinkAppInner extends PureComponent<{}, INewLinkState> {
    logoutTimer: LogoutTimer;
    pzApi: PasszeroApiV3;

    constructor(props: any) {
        super(props);

        this.state = {
            name: '',
            link: '',
            masterPassword: '',
            linkId: -1,
            isNewLink: true,
        };

        this.logoutTimer = new LogoutTimer();
        this.pzApi = new PasszeroApiV3();

        this.saveLink = this.saveLink.bind(this);
        this.handleNameChange = this.handleNameChange.bind(this);
        this.handleLinkChange = this.handleLinkChange.bind(this);
    }

    componentDidMount() {
        // start logout timer
        this.logoutTimer.startLogoutTimer();

        const masterPassword = readSavedMasterPassword();
        if (!masterPassword) {
            clientSideLogout();
            throw new Error('failed to load master password from storage');
        }

        // load link ID
        const linkId = Number.parseInt((document.getElementById('link_id') as HTMLInputElement).value, 10);
        console.log(`Got linkID ${linkId}`);
        let isNewLink = true;
        let serviceName = this.state.name;
        let linkValue = this.state.link;
        if (linkId > 0) {
            isNewLink = false;
            serviceName = (document.getElementById('service_name') as HTMLInputElement).value;
            linkValue = (document.getElementById('link_value') as HTMLInputElement).value;
        }

        this.setState({
            masterPassword: masterPassword,
            isNewLink: isNewLink,
            linkId: linkId,
            name: serviceName,
            link: linkValue,
        });
    }

    handleNameChange(event) {
        this.setState({
            name: event.target.value,
        });
    }

    handleLinkChange(event) {
        this.setState({
            link: event.target.value,
        });
    }

    saveNewLink() {
        const linkData = {
            link: {
                service_name: this.state.name,
                link: this.state.link,
            },
            password: this.state.masterPassword,
        };
        this.pzApi.saveLink(linkData)
            .then(() => {
                console.log('Link saved');
                window.location.assign('/links');
            })
            .catch((err) => {
                console.error('Failed to save link');
                console.error(err);
            });
    }

    editLink() {
        const linkData = {
            link: {
                service_name: this.state.name,
                link: this.state.link,
            },
            password: this.state.masterPassword,
        };
        this.pzApi.editLink(this.state.linkId, linkData)
            .then(() => {
                console.log('Link saved');
                window.location.assign('/links');
            })
            .catch((err) => {
                console.error('Failed to save link');
                console.error(err);
            });
    }

    saveLink() {
        if (this.state.isNewLink) {
            this.saveNewLink();
        } else {
            this.editLink();
        }
    }

    render() {
        let title = 'New Link';
        let buttonText = 'Save';
        if (!this.state.isNewLink) {
            title = 'Edit Link';
            buttonText = 'Update';
        }
        return (
            <div className="container">
                <h2 className="title">{ title }</h2>
                <form role="form" id="main-form">
                    <input type="text" className="link-service-name form-control"
                        required={true} name="service_name"
                        placeholder="Name"
                        value={ this.state.name }
                        onChange={ this.handleNameChange }/>
                    <input type="text" className="form-control"
                        required={true} name="link"
                        placeholder="Link"
                        value={ this.state.link }
                        onChange={ this.handleLinkChange }/>
                    <button type="button"
                        className="form-control btn btn-success"
                        onClick={ this.saveLink }>{ buttonText }</button>
                </form>
            </div>
        );
    }
}

const NewLinkApp = () => {
    return <LoggedInLayout>
        <NewLinkAppInner />
    </LoggedInLayout>;
};

export default NewLinkApp;
