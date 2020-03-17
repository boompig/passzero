import * as React from "react";
import PassZeroAPIv1 from "../common-modules/passzero-api-v1";

// instead of importing include it using a reference (since it's not a module)
// similarly for LogoutTimer variable
/// <reference path="../common/logoutTimer.ts" />

interface INewDocumentState {
    fileName: string;
    file: File;
    documentId: number;
    isNewDocument: boolean;
}

/**
 * Represents editing a new or existing link
 */
class NewDocumentApp extends React.Component<{}, INewDocumentState> {
    logoutTimer: LogoutTimer;
    pzAPI: PassZeroAPIv1;

    constructor(props: any) {
        super(props);

        this.state = {
            fileName: "",
            file: null,
            documentId: -1,
            isNewDocument: true,
        };

        this.logoutTimer = new LogoutTimer();
        this.pzAPI = new PassZeroAPIv1();

        this.saveDocument = this.saveDocument.bind(this);
        this.handleNameChange = this.handleNameChange.bind(this);
        this.handleFileChange = this.handleFileChange.bind(this);
    }

    componentDidMount() {
        // start logout timer
        this.logoutTimer.startLogoutTimer();

        // load link ID
        const documentId = Number.parseInt((document.getElementById("document_id") as HTMLInputElement).value, 10);
        console.log(`Got documentId ${documentId}`);
        let isNewDocument = true;
        if (documentId > 0) {
            isNewDocument = false;
        }

        this.setState({
            isNewDocument: isNewDocument,
            documentId: documentId,
        });
    }

    handleNameChange(event) {
        this.setState({
            fileName: event.target.value,
        });
    }

    handleFileChange(event) {
        this.setState({
            file: event.target.files[0],
        });
    }

    async saveNewDocument(event: React.SyntheticEvent) {
        event.preventDefault();
        const formData = new FormData();
        formData.append("document", this.state.file);
        const r = await this.pzAPI.createDocument(this.state.fileName, formData)
        if(r.ok) {
            console.log("Document saved");
            window.location.href = "/docs";
        } else {
            console.error("Failed to save document");
            console.error(r);
        }
        return false;
    }

    editDocument(event) {
        throw new Error("not implemented");
    }

    saveDocument(event: React.SyntheticEvent) {
        if (this.state.isNewDocument) {
            this.saveNewDocument(event);
        } else {
            this.editDocument(event);
        }
    }

    render() {
        if(this.state.isNewDocument) {
            let title = "New Document";
            let buttonText = "Save";
            if (!this.state.isNewDocument) {
                title = "Edit Document";
                buttonText = "Update";
            }
            return (
                <div className="container">
                    <h2 className="title">{ title }</h2>
                    <form role="form" id="main-form" onSubmit={this.saveDocument}>
                        <input type="text" className="document-filename form-control"
                            required={true} name="filename"
                            placeholder="Name"
                            value={ this.state.fileName }
                            onChange={ this.handleNameChange }/>
                        <input type="file" className="form-control"
                            required={true} name="file"
                            onChange={ this.handleFileChange }/>
                        <button type="submit"
                            className="form-control btn btn-success"
                            >{ buttonText }</button>
                    </form>
                </div>
            );
        } else {
            return <div className="alert alert-warning">
                <strong>Warning!</strong> Under construction
            </div>
        }
    }
}

export default NewDocumentApp;
