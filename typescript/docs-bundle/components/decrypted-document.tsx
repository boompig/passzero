import * as React from "react";
import {IDecryptedDocument} from "../interfaces";

interface IDecryptedDocumentProps {
    document: IDecryptedDocument;
    index: number;
    onDelete(index: number): void;
}

export default class DecryptedDocument extends React.Component<IDecryptedDocumentProps, {}> {
    constructor(props: IDecryptedDocumentProps) {
        super(props);

        this.handleEdit = this.handleEdit.bind(this);
        this.handleDelete = this.handleDelete.bind(this);
    }

    handleEdit(event) {
        window.location.href = `/links/${this.props.document.id}`;
    }

    handleDelete(event) {
        this.props.onDelete(this.props.index);
    }

    render() {
        return (
            <div className="document">
                <div className="document-name">{ this.props.document.name }</div>
                <div className="button-panel">
                    <button type="button" className="btn btn-warning"
                        onClick={ this.handleEdit }>Edit</button>
                    <button type="button" className="btn btn-danger"
                        onClick={ this.handleDelete }>Delete</button>
                </div>
            </div>
        );
    }
}
