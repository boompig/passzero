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
			"links": [],
			"linksLoaded": false,
			"apiKey": null,
		}

		this.logoutTimer = new LogoutTimer();
	}

	componentDidMount() {
		// TODO:
		// this.logoutTimer.startLogoutTimer();

		console.log("Fetching links...");
		// fetch all the encrypted links
		pzAPI.getEncryptedLinks()
			.then((response) => {
				console.log("links:");
				console.log(response);
				this.setState({
					"links": response.links,
					"apiKey": response.apiKey,
					"linksLoaded": true,
				});
			})
			.catch((err) => {
				console.error("Failed to get links");
				console.error(err);
			});
	}

	render() {
		if(!this.state.linksLoaded) {
			return <div>Loading links...</div>;
		}
		if(this.state.linksLoaded && this.state.links.length === 0) {
			return (
				<div>
					You don't have any saved links yet. Create some <a href="/links/new">here</a>.
				</div>
			);

		}
		return <div>Hello world</div>;
	}
}

export default App;