/* eslint-env node */

import * as React from "react";
import * as ReactDOM from "react-dom";
import pzAPI from "./passzero_api";
import LogoutTimer from "./logout_timer";

const logoutTimer = new LogoutTimer();

interface DocumentAppProps {};

/**
 * Top-level component for document storage
 */
class DocumentApp extends React.Component<DocumentAppProps, any> {

	constructor(props) {
		super(props);
		this.state = {
			docs: [],
			searchStr: "",
			docsLoaded: false,
			searchResults: []
		};

		// this is such a stupid pattern
		// only have to do this because javascript is terrible
		this.onSearch = this.onSearch.bind(this);
		this.uploadToServer = this.uploadToServer.bind(this);
		this.loadFromServer = this.loadFromServer.bind(this);
		this.onDocuments = this.onDocuments.bind(this);
		this.onMouseDown = this.onMouseDown.bind(this);
	}

	onMouseDown() {
		logoutTimer.reset();
	}

	loadFromServer() {
		pzAPI.getDocuments().then((documents) => {
			this.onDocuments(documents);
		});
	}

	// TODO set the event type properly here
	uploadToServer(event: any) {
		console.log(event.target.value);
		const options = {
			method: "POST",
			// send credential cookie
			credentials: "include",
			body: event.target.value
		};
		event.preventDefault();
	}

	/**
	 * Expect the parameters to be an array of docs
	 */
	onDocuments(documents) {
		console.log("Loaded docs:");
		console.log(documents);
		this.setState({
			docs: documents,
			docsLoaded: true,
			// on load, search results are all the documents
			searchResults: documents
		});
	}

	/**
	 * Documents loaded here
	 */
	componentDidMount() {
		this.loadFromServer();
		logoutTimer.start();
	}

	/**
	 * Performs the search using value in this.state.searchStr
	 * overtop this.state.docs
	 */
	performSearch() {
		if(this.state.searchStr === null || this.state.searchStr === "") {
			this.state.searchResults = this.state.docs;
			return;
		}
		const searchStr = this.state.searchStr.toLowerCase();
		this.state.searchResults = this.state.docs.filter((doc) => {
			const docName = doc.name.toLowerCase();
			return docName.indexOf(searchStr) !== -1;
		});
	}

	/**
	 * Sets the state when searchStr changes, then performs a search
	 */
	onSearch(searchStr) {
		this.setState({
			searchStr: searchStr
		}, this.performSearch);
		logoutTimer.reset();
	}

	render() {
		return (<div onMouseDown={ this.onMouseDown }>
			<h1 className="title">PassZero Documents</h1>

			<DocCount docsLoaded={ this.state.docsLoaded }
				docs={ this.state.docs } />
			
			<Search onSearch={ this.onSearch } />
			<SearchResults filteredDocs={ this.state.searchResults } />
		</div>);
	}
}

interface DocCountProps {
	docsLoaded: boolean;
	docs: Array<MyFile>;
}

class DocCount extends React.Component<DocCountProps, any> {
	constructor(props: any) {
		super(props);
	}

	render() {
		let doc = null;
		if(this.props.docs) {
			if(this.props.docs.length === 1) {
				doc = "document";
			} else {
				doc = "documents";
			}
		}
		return (
			<div id="num-docs">
				{ this.props.docsLoaded ?
					null :
					<span>Loading entries...</span> }
				{ this.props.docsLoaded && this.props.docs.length > 0 ? 
					<span>You have { this.props.docs.length } { doc }</span> :
					null }
				{ this.props.docsLoaded && this.props.docs.length === 0 ?
					<span>No documents yet!</span> :
					null }
			</div>
		);
	}
}

interface SearchProps {
	onSearch: (searchStr: string) => void;
}

class Search extends React.Component<SearchProps, any> {
	constructor(props) {
		super(props);
		this.onSearch = this.onSearch.bind(this);
	}

	/**
	 * Bubble up the value in this component to a higher component
	 */
	// TODO get the right event type here
	onSearch(event: any) {
		this.props.onSearch(event.target.value);
	}

	render() {
		return (<form id="search-form">
			<div className="form-group has-feedback">
				<input type="text" name="search" id="search" className="form-control"
					placeholder="search"
					onChange={ this.onSearch }
				/>
				<i className="glyphicon glyphicon-search form-control-feedback"></i>
			</div>
		</form>);
	}
}

interface MyFile {
	id: number;
	name: string;
}

interface SearchResultsProps {
	filteredDocs: Array<MyFile>;
}

class SearchResults extends React.Component<SearchResultsProps, any> {
	render() {
		let docs = [];
		for(let i = 0; i < this.props.filteredDocs.length; i++) {
			docs[i] = <Document
				key={ this.props.filteredDocs[i].id }
				name={ this.props.filteredDocs[i].name }
				id={ this.props.filteredDocs[i].id }
			/>;
		}

		return (<div id="doc-container">
			{ docs }
		</div>);
	}
}

interface DocumentProps {
	id: number;
	name: string;
	
	// TODO not sure if this is necessary
	key: any;
}

class Document extends React.Component<DocumentProps, any> {
	render() {
		return (<div className="doc" id={ "doc-" + this.props.id }>
			<div className="doc-name">{ this.props.name }</div>
			<div className="doc-panel">
				<a href={ window.location.href + "/" + this.props.id }
					className="btn btn-info">View</a>
				<button type="button" className="btn btn-danger">Delete</button>
			</div>
		</div>);
	}
}

ReactDOM.render(
	<DocumentApp />,
	document.getElementById("react-root")
);

// TODO not sure if there is a good way around this:
window.onfocus = () => { logoutTimer.check(); };
