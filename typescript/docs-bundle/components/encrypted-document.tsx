import * as React from "react";
import {IEncryptedDocument} from "../interfaces";

interface IEncDocProps {
    document: IEncryptedDocument;
    index: number;

    onDecrypt: (index: number) => void;
    onDelete: (index: number) => void;
}

export default class EncryptedDocument extends React.PureComponent<IEncDocProps, {}> {
    constructor(props: IEncDocProps) {
        super(props);

        this.handleEdit = this.handleEdit.bind(this);
        this.handleDecrypt = this.handleDecrypt.bind(this);
        this.handleDelete = this.handleDelete.bind(this);
    }

    handleEdit(event) {
        window.location.href = `/links/${this.props.document.id}`;
    }

    handleDecrypt() {
        this.props.onDecrypt(this.props.index);
    }

    handleDelete() {
        this.props.onDelete(this.props.index);
    }

    render() {
        return <div className="document">
            <div className="document-name">{ this.props.document.name }</div>
            <div className="button-panel">
                <button type="button" className="btn btn-info"
                    onClick={ this.handleDecrypt }>View</button>
                <button type="button" className="btn btn-warning"
                    onClick={ this.handleEdit }>Edit</button>
                <button type="button" className="btn btn-danger"
                    onClick={ this.handleDelete }>Delete</button>
            </div>
        </div>
    }
}