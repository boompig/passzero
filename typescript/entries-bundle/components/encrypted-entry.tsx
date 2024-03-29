import { Component } from 'react';
import * as React from 'react';
import { IEncryptedEntry } from '../../common-modules/entries';

interface IEncryptedEntryProps {
    entry: IEncryptedEntry;
    onDecrypt(entryId: number): void;
    onDelete(entryId: number): void;
}

interface IEncryptedEntryState {}

export default class EncryptedEntry extends Component<IEncryptedEntryProps, IEncryptedEntryState> {
    constructor(props: IEncryptedEntryProps) {
        super(props);

        this.handleDecrypt = this.handleDecrypt.bind(this);
        this.handleEdit = this.handleEdit.bind(this);
        this.handleDelete = this.handleDelete.bind(this);
    }

    handleDecrypt(): void {
        console.log(`Decrypt pressed for ID ${this.props.entry.id}`);
        this.props.onDecrypt(this.props.entry.id);
    }

    handleEdit(): void {
        window.location.assign(`/edit/${this.props.entry.id}`);
    }

    handleDelete(): void {
        console.log(`Deleting entry with ID ${this.props.entry.id}`);
        this.props.onDelete(this.props.entry.id);
    }

    render() {
        let accountElem = null;
        if (this.props.entry.service_link) {
            accountElem = <a className="entry-title account"
                href={this.props.entry.service_link}>{this.props.entry.account}</a>;
        } else {
            accountElem = <div className="entry-title account">{this.props.entry.account}</div>;
        }
        return (
            <div className="entry" id={ 'entry-' + this.props.entry.id }>
                { accountElem }
                <div className="entry-panel">
                    <button type="button" className="btn btn-warning edit-btn" onClick={ this.handleEdit }>Edit</button>
                    <button type="button" className="btn btn-primary decrypt-btn" onClick={ this.handleDecrypt }>Decrypt</button>
                    <button type="button" className="btn btn-danger" onClick={ this.handleDelete }>Delete</button>
                </div>
            </div>
        );
    }
}
