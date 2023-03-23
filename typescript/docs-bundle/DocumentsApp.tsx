import { Component } from "react";
import * as React from "react";
import EncryptedDocument from "./components/encrypted-document";
import { IEncryptedDocument, IDocument } from "./interfaces";
import PassZeroAPIv1 from "../common-modules/passzero-api-v1";
import LogoutTimer from "../common-modules/logoutTimer";

// import "bootstrap/dist/css/bootstrap.min.css";

const LoadingDocumentsApp = () => {
    return <div>Loading documents...</div>;
};

const EmptyDocumentsApp = () => {
    return (
        <div>
            You don't have any saved documents yet. Create some <a href="/docs/new">here</a>.
        </div>
    );
};

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
        this.renderDocuments = this.renderDocuments.bind(this);
        this.resetTimer = this.resetTimer.bind(this);
    }

    componentDidMount() {
        this.logoutTimer.startLogoutTimer();

        console.debug("Fetching documents...");
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
                    window.location.assign("/login");
                } else {
                    console.log("different type of error: " + err.name);
                }
            });
    }

    async handleDelete(index: number): Promise<void> {
        if(window.confirm("Do you really want to delete this document?")) {
            const doc = this.state.documents[index];
            console.log(`Deleting document with ID ${doc.id}...`);
            const r = await this.pzAPI.deleteDocument(doc.id)
            if(r.ok) {
                console.log("Deleted document successfully");
                const newDocs = [...this.state.documents.slice(0, index),
                    ...this.state.documents.slice(index + 1)
                ];
                // force state reload
                this.setState({
                    documents: newDocs,
                });
            } else {
                console.error("Deletion failed");
                console.error(r);
            }
        } else {
            console.log("not deleting - user aborted");
        }
    }

    handleDecrypt(index: number): void {
        const doc = this.state.documents[index];
        window.location.assign(`/docs/${doc.id}/view`);
    }

    resetTimer(): void {
        this.logoutTimer.resetLogoutTimer();
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
            <div onScroll={this.resetTimer} onClick={this.resetTimer}>
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
            return <LoadingDocumentsApp />;
        } else if (this.state.isDocumentsLoaded && this.state.documents.length === 0) {
            return <EmptyDocumentsApp />;
        } else {
            return this.renderDocuments();
        }
    }
}

export default DocumentApp;
