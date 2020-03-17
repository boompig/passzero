import { Component } from "react";
import * as React from "react";
import EncryptedDocument from "./components/encrypted-document";
import { IEncryptedDocument, IDocument } from "./interfaces";
import PassZeroAPIv1 from "../common-modules/passzero-api-v1";

// import "bootstrap/dist/css/bootstrap.min.css";

// instead of importing, include it using a reference (since it's not a module)
// similarly for LogoutTimer variable
/// <reference path="../common/logoutTimer.ts" />

interface IProps {}


interface IState {
    documents: IDocument[];
    // true iff the encrypted documents have been loaded from the server
    isDocumentsLoaded: boolean;
    // true iff currently decrypting something
    // isDecrypting: boolean;
}

class DocumentApp extends Component<IProps, IState> {
    logoutTimer: LogoutTimer | null;
    pzAPI: PassZeroAPIv1;

    constructor(props: any) {
        super(props);

        this.state = {
            documents: [],
            isDocumentsLoaded: false,
            // isDecrypting: false,
        };

        this.logoutTimer = new LogoutTimer();
        this.pzAPI = new PassZeroAPIv1();

        // javascript is terrible
        this.handleDecrypt = this.handleDecrypt.bind(this);
        this.handleDelete = this.handleDelete.bind(this);
        this.renderLoading = this.renderLoading.bind(this);
        this.renderEmpty = this.renderEmpty.bind(this);
        this.renderDocuments = this.renderDocuments.bind(this);
    }

    componentDidMount() {
        this.logoutTimer.startLogoutTimer();

        console.log("Fetching documents...");
        // fetch all the encrypted links
        this.pzAPI.getEncryptedDocuments()
            .then((response) => {
                console.log("documents:");
                console.log(response);

                // alter each link to set encrypted = true
                for (const doc of response) {
                    doc.isEncrypted = true;
                }

                this.setState({
                    documents: response,
                    isDocumentsLoaded: true,
                });
            })
            .catch((err) => {
                console.error("Failed to get documents");
                console.error(err);
                if (err.name === "UnauthorizedError") {
                    window.location.href = "/login";
                } else {
                    console.log("different type of error: " + err.name);
                }
            });
    }

    renderLoading() {
        return <div>Loading documents...</div>;
    }

    renderEmpty() {
        return (
            <div>
                You don't have any saved documents yet. Create some <a href="/docs/new">here</a>.
            </div>
        );
    }

    handleDelete(linkIndex: number): void {
        throw Error("not implemented");
        // const link = this.state.links[linkIndex];
        // console.log(`Deleting link with ID ${link.id}...`);
        // this.pzApi.deleteLink(link.id)
        //     .then((response) => {
        //         console.log("Got decrypted link from server");
        //         const newLinks = this.state.links;
        //         newLinks.splice(linkIndex, 1);
        //         // force state reload
        //         this.setState({
        //             links: newLinks,
        //         });
        //     });
    }

    handleDecrypt(index: number): void {
        const doc = this.state.documents[index];
        window.location.href = `/docs/${doc.id}/view`;
    }

    /**
     * This method is called when links are loaded and this.state.links is non-empty
     */
    renderDocuments() {
        const docElems = [];
        for (let i = 0; i < this.state.documents.length; i++) {
            const doc = this.state.documents[i];
            let docElem = null;
            if (doc.isEncrypted) {
                docElem = <EncryptedDocument document={ doc as IEncryptedDocument } index={ i }
                    key={`encrypted-document-${i}`}
                    onDecrypt={ this.handleDecrypt }
                    onDelete={ this.handleDelete }/>;
            } else {
                // should not be here
                throw new Error("somehow got a decrypted document...");
            }
            docElems.push(docElem);
        }

        return (
            <div>
                <div className="docs-control-panel">
                    <a href="/docs/new" className="new-doc-btn control-panel-btn btn btn-lg btn-success">
                        Create New Document
                    </a>
                </div>
                <div className="document-container">
                    { docElems }
                </div>
            </div>
        );
    }

    render() {
        if (!this.state.isDocumentsLoaded) {
            return this.renderLoading();
        } else if (this.state.isDocumentsLoaded && this.state.documents.length === 0) {
            return this.renderEmpty();
        } else {
            return this.renderDocuments();
        }
    }
}

export default DocumentApp;
