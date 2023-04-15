import * as React from 'react';
import { IDecryptedLink } from '../../common-modules/links';

interface IDecryptedLinkProps {
    link: IDecryptedLink;
    index: number;
    onDelete(index: number): void;
}

export const DecryptedLink = (props: IDecryptedLinkProps) => {
    const handleEdit = (event: React.SyntheticEvent) => {
        window.location.assign(`/links/${props.link.id}`);
    };

    const handleDelete = (event: React.SyntheticEvent) => {
        props.onDelete(props.index);
    };

    return (
        <div className="link">
            {/* NOTE: the noreferrer and noopener attributes are very important for privacy */}
            {/* see: https://developer.mozilla.org/en-US/docs/Web/HTML/Element/a#security_and_privacy */}
            <a href={props.link.link} className="link-service-name" target="_blank" rel="noreferrer noopener">
                {props.link.service_name}
                <span className="fas fa-external-link-alt"></span>
            </a>
            <div className="button-panel">
                <button type="button" className="btn btn-warning"
                    onClick={ handleEdit }>Edit</button>
                <button type="button" className="btn btn-danger"
                    onClick={ handleDelete }>Delete</button>
            </div>
        </div>
    );
};

export default DecryptedLink;
