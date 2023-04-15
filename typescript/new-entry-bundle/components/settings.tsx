import { PureComponent } from 'react';
import * as React from 'react';
import { FontAwesomeIcon } from '@fortawesome/react-fontawesome';
import { library } from '@fortawesome/fontawesome-svg-core';
import { faCheck, faTimes } from '@fortawesome/free-solid-svg-icons';

library.add(faCheck, faTimes);

interface ISettingsProps {
    genMode: string;
    onGenModeChange(newMode: string): void;
    passwordLength: number;
    onPasswordLengthChange(length: number): void;
    useSpecialChars: boolean;
    toggleUseSpecialChars(): void;
    phraseLength: number;
    onPhraseLengthChange(length: number): void;
}

export class Settings extends PureComponent<ISettingsProps, any> {
    constructor(props: ISettingsProps) {
        super(props);

        // javascript is stupid
        this.handleGenModeChange = this.handleGenModeChange.bind(this);
    }

    handleGenModeChange(event) {
        this.props.onGenModeChange(event.target.value);
    }

    render() {
        let genSettings = null;
        if (this.props.genMode === 'password') {
            const classes = this.props.useSpecialChars ? 'btn-success' : 'btn-warning';
            const glyphClass = this.props.useSpecialChars ? 'check' : 'times';

            genSettings = (<div className="password-settings form-group">
                <h5>Password Settings</h5>
                <div className="form-group">
                    <span className="text">Characters in Password { this.props.passwordLength }</span>
                    <input type="range" className="input-range" min={ 6 } max={ 32 } step={ 1 }
                        value={ this.props.passwordLength }
                        onChange={ (e) => this.props.onPasswordLengthChange(Number.parseInt(e.target.value)) } />
                </div>

                <button type="button"
                    className={ `btn ${classes} toggle-special-chars-btn` }
                    onClick={ (e) => this.props.toggleUseSpecialChars() }>
                    <FontAwesomeIcon icon={['fas', glyphClass]} />
                    <span>Use special characters</span>
                </button>
            </div>);
        } else {
            genSettings = (<div className="passphrase-settings form-group">
                <h5>Passphrase Settings</h5>

                <div className="form-group">
                    <span className="text">Number of Words: { this.props.phraseLength }</span>
                    <input type="range" className="input-range" min={ 4 } max={ 8 } step={ 1 }
                        value={ this.props.phraseLength }
                        onChange={ (e) => this.props.onPhraseLengthChange(Number.parseInt(e.target.value)) } />
                </div>
            </div>);
        }

        return (
            <div id="settings-container" className="form-group">
                <div className="form-group">
                    <h5>Password generation mode</h5>
                    <div className="form-check">
                        <input className="form-check-input"
                            type="radio"
                            name="passwordGenMode"
                            id="gen-mode-password"
                            value="password"
                            checked={this.props.genMode === 'password'}
                            onChange={ this.handleGenModeChange } />
                        <label className="form-check-label" htmlFor="#gen-mode-password">Password</label>
                    </div>
                    <div className="form-check">
                        <input className="form-check-input"
                            type="radio"
                            name="passwordGenMode"
                            id="gen-mode-phrase"
                            value="phrase"
                            checked={this.props.genMode === 'phrase'}
                            onChange={ this.handleGenModeChange } />
                        <label className="form-check-label" htmlFor="#gen-mode-phrase">Phrase</label>
                    </div>
                </div>

                { genSettings }
            </div>
        );
    }
}
