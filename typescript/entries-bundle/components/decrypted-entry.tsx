import {Component} from 'react';
import * as React from 'react';
import * as ReactTooltip from 'react-tooltip';
import {IDecryptedEntry} from './entries';

interface IDecryptedEntryProps {
    onDelete(entryId: number): void;
    entry: IDecryptedEntry;
}

interface IDecryptedEntryState {
    isPasswordHidden: boolean;

    isTooltipHidden: boolean;
    tooltipLastShown: Date | null;
};

export default class DecryptedEntry extends Component<IDecryptedEntryProps, IDecryptedEntryState> {
    passwordFieldRef: React.RefObject<HTMLInputElement>;
    copyTooltipRef: React.RefObject<HTMLButtonElement>;

    tooltipHideDelay: number;

    constructor(props: IDecryptedEntryProps) {
        super(props);

        this.state = {
            isPasswordHidden: true,

            // tooltip stuff
            isTooltipHidden: true,
            tooltipLastShown: null,
        };

        this.tooltipHideDelay = 2600;

        this.passwordFieldRef = React.createRef();
        this.copyTooltipRef = React.createRef();

        this.toggleHidePassword = this.toggleHidePassword.bind(this);
        this.hideTooltip = this.hideTooltip.bind(this);
        this.handleCopy = this.handleCopy.bind(this);
        this.handleDelete = this.handleDelete.bind(this);
        this.handleEdit = this.handleEdit.bind(this);
    }

    hideTooltip() {
        const now = new Date();
        const diff = now.valueOf() - (this.state.tooltipLastShown as Date).valueOf();
        if(diff >= this.tooltipHideDelay) {
            ReactTooltip.hide(this.copyTooltipRef.current);
            // console.log('Hiding tooltip');
            this.setState({
                isTooltipHidden: true,
            });
        } else {
            window.setTimeout(this.hideTooltip, diff);
        }
    }

    handleCopy(event: React.SyntheticEvent): void {
        // console.log('Copy button pressed');
        // console.log(this.passwordFieldRef.current);
        // select the copy button
        this.passwordFieldRef.current.select();
        document.execCommand('copy');

        ReactTooltip.show(this.copyTooltipRef.current);
        this.setState({
            tooltipLastShown: new Date(),
            isTooltipHidden: false,
        });
        window.setTimeout(this.hideTooltip, this.tooltipHideDelay);

        // focus back on the button
        (event.target as HTMLButtonElement).focus();
    }

    handleDelete(): void {
        this.props.onDelete(this.props.entry.id);
    }

    handleEdit(): void {
        window.location.href = `/edit/${this.props.entry.id}`;
    }

    toggleHidePassword(): void {
        let isPasswordHidden = !this.state.isPasswordHidden;
        this.setState({
            isPasswordHidden: isPasswordHidden
        });
    }

    render() {
        // the password field
        let password = null, extra = null;
        if(this.state.isPasswordHidden) {
            password = (<input type='text' readOnly={true} value={ this.props.entry.password }
                className='form-control password hidden-toggle text-hidden'
                ref={ this.passwordFieldRef } />
            );
            extra = (
                <div className='extra hidden-toggle text-hidden'>{ this.props.entry.extra}</div>
            );
        } else {
            password = (<input type='text' readOnly={true} value={ this.props.entry.password }
                className='form-control password hidden-toggle'
                ref={ this.passwordFieldRef } />
            );
            extra = (
                <div className='extra hidden-toggle'>{ this.props.entry.extra}</div>
            );
        }

        return (
            <div className='entry' id={ `entry-${this.props.entry.id}` }>
                <div className='entry-title account'>{ this.props.entry.account }</div>
                <div className='username'>{ this.props.entry.username }</div>
                { password }
                { this.props.entry.extra ?
                    (<div className='extra-container'>
                        <label htmlFor='extra'>Extra Info</label>
                        { extra }
                    </div>) : null}
                <div className='entry-panel'>
                    <ReactTooltip
                        effect='solid'
                        id={`copy-tooltip-${this.props.entry.id}`}></ReactTooltip>
                    <button type='button' className='btn btn-success copy-pwd-btn'
                        onClick={ this.handleCopy }
                        ref={ this.copyTooltipRef }
                        data-tip='Copied'
                        data-event='dblclick'
                        data-for={ `copy-tooltip-${this.props.entry.id}` }>
                        Copy Password
                    </button>
                    <button type='button' className='btn btn-warning edit-btn' onClick={ this.handleEdit }>Edit</button>
                    <button type='button' className='btn btn-info show-hide-btn' onClick={ this.toggleHidePassword }>
                        { this.state.isPasswordHidden ? 'Show' : 'Hide' }
                    </button>
                    <button type='button' className='btn btn-danger' onClick={ this.handleDelete }>Delete</button>
                </div>
            </div>
        );
    }
}