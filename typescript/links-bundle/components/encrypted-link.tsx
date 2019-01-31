import * as React from 'react';
import {IEncryptedLink} from './links'

interface IEncryptedLinkProps {
    link: IEncryptedLink;
    index: number;
    onDecrypt(index: number): void;
    onDelete(index: number): void;
}

export default class EncryptedLink extends React.Component<IEncryptedLinkProps, {}> {
    constructor(props: IEncryptedLinkProps) {
        super(props);

        this.handleEdit = this.handleEdit.bind(this);
        this.handleDecrypt = this.handleDecrypt.bind(this);
        this.handleDelete = this.handleDelete.bind(this);
	}

    handleEdit(event) {
        window.location.href = `/links/${this.props.link.id}`;
    }

    handleDecrypt(event) {
        this.props.onDecrypt(this.props.index);
    }

    handleDelete(event) {
        this.props.onDelete(this.props.index);
	}

    render() {
        return (
            <div className='link'>
                <div className='link-id'>Link #{ this.props.link.id }</div>
                <div className='button-panel'>
                    <button type='button' className='btn btn-info'
                        onClick={ this.handleDecrypt }>Decrypt</button>
                    <button type='button' className='btn btn-warning'
                        onClick={ this.handleEdit }>Edit</button>
                    <button type='button' className='btn btn-danger'
                        onClick={ this.handleDelete }>Delete</button>
                </div>
            </div>
        );
    }
}