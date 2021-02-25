import * as moment from "moment";
import {Component} from "react";
import * as React from "react";
import ReactTooltip from "react-tooltip";
import {IDecryptedEntry} from "./entries";

interface IDecryptedEntryProps {
    entry: IDecryptedEntry;
    onDelete(entryId: number): void;
}

interface IDecryptedEntryState {
    isPasswordHidden: boolean;

    isTooltipHidden: boolean;
    tooltipLastShown: Date | null;
}

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
        if (diff >= this.tooltipHideDelay) {
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
        // focus first due to weird iOS stuff
        this.passwordFieldRef.current.focus();
        // after focus can actually select
        /*
         * NOTE: commented out code below does *not work* on mobile safari
         * see https://stackoverflow.com/a/6302507/755934
         */
        // this.passwordFieldRef.current.select();
        this.passwordFieldRef.current.setSelectionRange(0, 9999);
        // finally copy the text
        document.execCommand("copy");

        ReactTooltip.show(this.copyTooltipRef.current);
        this.setState({
            tooltipLastShown: new Date(),
            isTooltipHidden: false,
        });
        window.setTimeout(this.hideTooltip, this.tooltipHideDelay);

        // focus back on the button to keep text from being selected
        (event.target as HTMLButtonElement).focus();
    }

    handleDelete(): void {
        this.props.onDelete(this.props.entry.id);
    }

    handleEdit(): void {
        window.location.href = `/edit/${this.props.entry.id}`;
    }

    toggleHidePassword(): void {
        const isPasswordHidden = !this.state.isPasswordHidden;
        this.setState({
            isPasswordHidden: isPasswordHidden
        });
    }

    render() {
        // the password field
        let password = null;
        let extra = null;
        if (this.state.isPasswordHidden) {
            password = (
                <form>
                    <input type="text" value={this.props.entry.password}
                        readOnly={true}
                        className="form-control password hidden-toggle text-hidden"
                        ref={this.passwordFieldRef} />
                </form>);
            extra = (
                <div className="extra hidden-toggle text-hidden">{ this.props.entry.extra}</div>
            );
        } else {
            password = (
                <form>
                    <input type="text" value={this.props.entry.password}
                        readOnly={true}
                        className="form-control password hidden-toggle"
                        ref={this.passwordFieldRef} />
                </form>
            );
            extra = (
                <div className="extra hidden-toggle">{ this.props.entry.extra}</div>
            );
        }
        let accountElem = null;
        if (this.props.entry.service_link) {
            accountElem = <a className="entry-title account"
                href={this.props.entry.service_link}>{this.props.entry.account}</a>;
        } else {
            accountElem = <div className="entry-title account">{this.props.entry.account}</div>;
        }
        let lastModifiedElem = null;
        if (this.props.entry.last_modified) {
            const lastModified = moment(this.props.entry.last_modified * 1000);
            const s = lastModified.fromNow();
            let cls = "badge-success";
            if (lastModified <= moment().subtract(5, "years")) {
                cls = "badge-danger";
            } else if (lastModified <= moment().subtract(1, "years")) {
                cls = "badge-warning";
            }
            lastModifiedElem = <div className={"badge last-modified " + cls}>
                Last modified {s}
            </div>;
        }

        return (
            <div className="entry" id={ `entry-${this.props.entry.id}` }>
                {lastModifiedElem}
                {accountElem}
                <div className="username">{ this.props.entry.username }</div>
                { password }
                { this.props.entry.extra ?
                    (<div className="extra-container">
                        <label htmlFor="extra">Extra Info</label>
                        { extra }
                    </div>) : null}
                <div className="entry-panel">
                    <ReactTooltip
                        effect="solid"
                        id={`copy-tooltip-${this.props.entry.id}`}></ReactTooltip>
                    <button type="button" className="btn btn-success copy-pwd-btn"
                        onClick={ this.handleCopy }
                        ref={ this.copyTooltipRef }
                        data-tip="Copied"
                        data-event="dblclick"
                        data-for={ `copy-tooltip-${this.props.entry.id}` }>
                        Copy Password
                    </button>
                    <button type="button" className="btn btn-warning edit-btn" onClick={ this.handleEdit }>Edit</button>
                    <button type="button" className="btn btn-info show-hide-btn" onClick={ this.toggleHidePassword }>
                        { this.state.isPasswordHidden ? "Show" : "Hide" }
                    </button>
                    <button type="button" className="btn btn-danger" onClick={ this.handleDelete }>Delete</button>
                </div>
            </div>
        );
    }
}
