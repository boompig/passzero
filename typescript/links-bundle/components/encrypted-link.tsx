import * as React from 'react';
import { IEncryptedLink } from '../../common-modules/links';

interface IEncryptedLinkProps {
    link: IEncryptedLink;
    index: number;
    /**
     * Whether the app is currently decrypting something
     * This should disable some interactions
     */
    isDecrypting: boolean;
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
        window.location.assign(`/links/${this.props.link.id}`);
    }

    handleDecrypt(event) {
        this.props.onDecrypt(this.props.index);
    }

    handleDelete(event) {
        this.props.onDelete(this.props.index);
    }

    render() {
        return (
            <div className="link">
                <div className="link-id">Link #{ this.props.link.id }</div>
                <div className="button-panel">
                    <button type="button" className="btn btn-primary"
                        disabled={ this.props.isDecrypting }
                        onClick={ this.handleDecrypt }>Decrypt</button>
                    <button type="button" className="btn btn-warning"
                        onClick={ this.handleEdit }>Edit</button>
                    <button type="button" className="btn btn-danger"
                        onClick={ this.handleDelete }>Delete</button>
                </div>
            </div>
        );
    }
}
