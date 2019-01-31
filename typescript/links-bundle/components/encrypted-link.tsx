import * as React from 'react';
import {IEncryptedLink} from './links'

interface IEncryptedLinkProps {
	link: IEncryptedLink;
	index: number;
	onDecrypt(index: number): void;
}

export default class EncryptedLink extends React.Component<IEncryptedLinkProps, {}> {
	constructor(props: IEncryptedLinkProps) {
		super(props);

		this.handleDecrypt = this.handleDecrypt.bind(this);
	}

	handleDecrypt(event) {
		this.props.onDecrypt(this.props.index);
	}

	render() {
		return (
			<div className='link'>
				<div className='link-id'>Link #{ this.props.link.id }</div>
				<div className='button-panel btn-group'>
					<button type='button' className='btn btn-info'
						onClick={ this.handleDecrypt }>Decrypt</button>
				</div>
			</div>
		);
	}
}