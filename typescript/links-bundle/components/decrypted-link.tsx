import * as React from 'react';
import {IDecryptedLink} from './links';

interface IDecryptedLinkProps {
    link: IDecryptedLink;
    index: number;
    onDelete(index: number): void;
}

export default class DecryptedLink extends React.Component<IDecryptedLinkProps, {}> {
    constructor(props: IDecryptedLinkProps) {
        super(props);

        this.handleEdit = this.handleEdit.bind(this);
        this.handleDelete = this.handleDelete.bind(this);
    }

    handleEdit(event) {
        window.location.href = `/links/${this.props.link.id}`;
    }

    handleDelete(event) {
        this.props.onDelete(this.props.index);
    }

    render() {
        return (
            <div className='link'>
                <a href={ this.props.link.link} className='link-service-name'>{ this.props.link.service_name }</a>
                <div className='button-panel'>
                    <button type='button' className='btn btn-warning'
                        onClick={ this.handleEdit }>Edit</button>
                    <button type='button' className='btn btn-danger'
                        onClick={ this.handleDelete }>Delete</button>
                </div>
            </div>
        );
    }
}