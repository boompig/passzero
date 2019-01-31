import { Component } from 'react';
import * as React from 'react';

// instead of importing passzero_api, include it using a reference (since it's not a module)
// introduces pzAPI variable
/// <reference path="../common/passzero_api.ts" />
// similarly for LogoutTimer variable
/// <reference path="../common/logoutTimer.ts" />

class App extends Component<any, any> {
    logoutTimer: LogoutTimer;

    constructor(props: any) {
        super(props);

        this.state = {
            name: "",
            link: "",
            masterPassword: "",
        };

        this.logoutTimer = new LogoutTimer();

        this.saveLink = this.saveLink.bind(this);
        this.handleNameChange = this.handleNameChange.bind(this);
        this.handleLinkChange = this.handleLinkChange.bind(this);
    }


    componentDidMount() {
        // start logout timer
        this.logoutTimer.startLogoutTimer();

        // load master password
        const masterPassword = (document.getElementById("master_password") as HTMLInputElement).value;
        console.log(masterPassword);
        this.setState({
            masterPassword: masterPassword,
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

    saveLink() {
        const linkData = {
            link: {
                service_name: this.state.name,
                link: this.state.link
            },
            password: this.state.masterPassword
        };
        pzAPI.saveLink(linkData)
            .then(() => {
                console.log("Link saved");
                window.location.href = "/links";
            })
            .catch((err) => {
                console.error("Failed to save link");
                console.error(err)
            });
    }

    render() {
        return (
            <div className="container">
                <h2 className="title">New Link</h2>
                <form role="form" id="main-form">
                    <input type="text" className="form-control"
                        required={true} name="service_name"
                        placeholder="Name"
                        onChange={ this.handleNameChange }/>
                    <input type="text" className="form-control"
                        required={true} name="link"
                        placeholder="Link"
                        onChange={ this.handleLinkChange }/>
                    <button type="button"
                        className="form-control btn btn-success"
                        onClick={ this.saveLink }>Save</button>
                </form>
            </div>
        );
    }
}

export default App;