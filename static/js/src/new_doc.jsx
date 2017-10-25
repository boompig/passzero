import React from "react";
import ReactDOM from "react-dom";
import Dropzone from "react-dropzone";
import pzAPI from "./passzero_api_module.js";

/**
 * Top-level component for document storage
 */
class DocumentUploadApp extends React.Component {
	getIdFromUrl() {
		const parts = window.location.href.split("/");
		if(parts.length === 0) {
			return null;
		}
		const maybeId = Number(parts[parts.length - 1]);
		if(isNaN(maybeId)) {
			return null;
		} else {
			return maybeId;
		}
	}

	constructor(props) {
		super(props);
		this.state = {
			"id": this.getIdFromUrl(),
			"file": null,
			"loadingDoc": false
		};
		this.uploadToServer = this.uploadToServer.bind(this);
		this.onDrop = this.onDrop.bind(this);
		this.resetDoc = this.resetDoc.bind(this);
		this.onDocumentLoad = this.onDocumentLoad.bind(this);
	}

	/**
	 * Expecting props to have the following keys:
	 *		- fileName: string
	 *		- file: File object
	 */
	uploadNewDocument(props) {
		console.log("Uploading document to server now...");
		console.log(props);
		pzAPI.createDocument(props.fileName, props.file)
			.then((response) => {
				console.log(response);
			}).catch((response) => {
				console.error("Failed to upload document");
				console.error(response);
			});
	}

	/**
	 * Expecting props to have the following keys:
	 *		- fileName: string
	 *		- file: File object
	 */
	editExistingDocument(props) {
		console.log("Uploading document to server now...");
		console.log(props);
		pzAPI.editDocument(this.state.id, props.fileName, props.file)
			.then((response) => {
				console.log(response);
			}).catch((response) => {
				console.error("Failed to edit existing document");
				console.error(response);
			});
	}

	uploadToServer(props) {
		if(this.state.id) {
			return this.editExistingDocument(props);
		} else {
			return this.uploadNewDocument(props);
		}
	}

	/**
	 * Create a blob *correctly* from a base64-encoded string returned from the server
	 * reference here: https://stackoverflow.com/a/16245768/755934
	 */
	blobFromBase64(contents, contentType) {
		const s = window.atob(contents);
		const byteNumbers = new Array(s.length);
		for(let i = 0; i < byteNumbers.length; i++) {
			byteNumbers[i] = s.charCodeAt(i);
		}
		const byteArray = new Uint8Array(byteNumbers);
		return new Blob([byteArray], {"type": contentType});
	}

	onDocumentLoad(response) {
		console.log("Received file:");
		console.log(response);
		//TODO content-type hard-coded for now
		const blob = this.blobFromBase64(response.contents, "image/jpeg");
		console.log(blob);
		const file = new File([blob], response.name, { "type": blob.type });
		console.log(file);
		file.preview = URL.createObjectURL(file);
		this.setState({
			"file": file
		}, () => {
			console.log("new file:");
			console.log(this.state.file);
		});
	}

	/**
	 * Documents loaded here
	 */
	componentDidMount() {
		if(this.state.id) {
			console.log("Loading document details from server...");
			this.setState({
				"loadingDoc": true
			});
			pzAPI.getDocument(this.state.id)
				.then((response) => {
					this.onDocumentLoad(response);
					this.setState({
						"loadingDoc": false
					});
				});
		}
	}

	onDrop(acceptedFiles, rejectedFiles) {
		if(acceptedFiles.length > 0) {
			this.setState({
				"file": acceptedFiles[0]
			}, () => {
				console.log("added file " + acceptedFiles[0].name + " to dropzone");
			});
		}
		if(rejectedFiles.length > 0) {
			console.log("Rejected files:");
			console.log(rejectedFiles);
		}
	}

	resetDoc() {
		this.setState({
			"file": null
		});
	}

	render() {
		if(this.state.file) {
			return (
				<div>
					<h1 className="title">New Document</h1>
					<UploadDocumentForm
						file={ this.state.file }
						onSubmit={ this.uploadToServer } 
						resetDoc={ this.resetDoc }
						existing={ this.state.id !== null } />
				</div>);
		} else if(this.state.id && this.state.loadingDoc) {
			// file has not yet loaded
			return <div>Loading document...</div>;
		} else {
			return (
				<div>
					<h1 className="title">New Document</h1>
					<p>Please upload a document</p>
					<Dropzone onDrop={ this.onDrop } />
				</div>);
		}
	}
}

/**
 * Expects the following props:
 * - file: a File object
 *		- name
 *		- preview (a URL)
 *		- size (in bytes)
 *	- onSubmit: function to call when document is ready to submit
 *	- resetDoc: function to call when you want to discard this document
 *	- existing: bool (true -> document already exists)
 */
class UploadDocumentForm extends React.Component {
	constructor(props) {
		super(props);
		this.state = {
			"fileName": this.props.file.name
		};
		this.onNameChange = this.onNameChange.bind(this);
		this.submitDoc = this.submitDoc.bind(this);
	}

	onNameChange(e) {
		this.setState({
			"fileName": e.target.value
		});
	}

	submitDoc(e) {
		e.preventDefault();
		this.props.onSubmit({
			"fileName": this.state.fileName,
			"file": this.props.file
		});
	}

	render() {
		let fileSizeKb = Math.ceil(this.props.file.size / 1024);
		let doc = <iframe className="doc-preview"
			src={ this.props.file.preview } width="1000" height="600"></iframe>;
		if(this.props.file.type === "image/jpeg") {
			doc = <img className="doc-preview" src={ this.props.file.preview } width="800" />;
		}
		return (
			<form role="form" onSubmit={ this.submitDoc }>
				<label htmlFor="name">Name</label>
				<input name="name" type="text" className="form-control" 
					value={ this.state.fileName }
					placeholder="name" required="true"
					onChange={ this.onNameChange } />
				<label htmlFor="size">File Size</label>
				<input name="size" type="text" className="form-control"
					value={ fileSizeKb + " KB" } readOnly="true" />
				<label htmlFor="doc">Preview</label>
				{ doc }
				<div>
					<button type="button" className="btn btn-warning"
						onClick={ this.props.resetDoc }>Change Document</button>
					<button type="submit" className="btn btn-success">
						{ this.props.existing ? "Save" : "Upload" }
					</button>
				</div>
			</form>
		);
	}
}

class Document extends React.Component {
	render() {
		return <h1>hello</h1>;
	}
}

ReactDOM.render(
	<DocumentUploadApp />,
	document.getElementById("react-root")
);
