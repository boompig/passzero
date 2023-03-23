import { PureComponent } from "react";
import * as React from "react";
import ReactTooltip from "react-tooltip";
import { Settings } from "./components/settings";
import PasszeroApiV3 from "../common-modules/passzero-api-v3";
import { random } from "lodash";
import classnames from "classnames";
import LogoutTimer from "../common-modules/logoutTimer";

interface INewEntryState {
	id: number;
	account: string;
	username: string;
	password: string;
	extra: string;
	has_2fa: boolean;
	version: number;

	formErrors: {[key: string]: string};
	errorMsg: string;

	isEntryNew: boolean;

	masterPassword: string;

	useSpecialChars: boolean;
	numWords: number;
	passwordGenMode: string;
	passwordLength: number;
	words: string[];

	isPasswordVisible: boolean;
	isSettingsVisible: boolean;
	isTooltipHidden: boolean;
	tooltipLastShown: Date | null;
}

interface IUserPrefs {
	default_random_passphrase_length: number;
	default_random_password_length: number;
}

// see ENTRY_LIMITS in config.py
const ENTRY_LIMITS = {
	account: 100,
	username: 100,
	password: 256,
	extra: 4096
}

class NewEntryApp extends PureComponent<{}, INewEntryState> {
	logoutTimer: LogoutTimer;
	pzApi: PasszeroApiV3;

	passwordFieldRef: React.RefObject<HTMLInputElement>;
	copyTooltipRef: React.RefObject<HTMLButtonElement>;

	tooltipHideDelay: number;

	dictionary: string;

	/**
	 * Two character sets that are generated on creation
	 * Should be fast
	 */
	charsets: any;

	constructor(props: any) {
		super(props);

		this.state = {
			// entry
			id: -1,
			account: "",
			username: "",
			password: "",
			extra: "",
			has_2fa: false,
			version: -1,

			// form validation errors
			formErrors: {},

			/**
			 * Error message received from the server
			 */
			errorMsg: null,

			isEntryNew: true,

			masterPassword: "",

			// settings for password generation
			useSpecialChars: true,
			numWords: 5,
			passwordGenMode: "password",
			passwordLength: 16,
			words: [],

			// UI
			isPasswordVisible: false,
			isSettingsVisible: false,
			isTooltipHidden: true,
			tooltipLastShown: null,
		};

		this.pzApi = new PasszeroApiV3();

		this.passwordFieldRef = React.createRef();
		this.copyTooltipRef = React.createRef();

		this.tooltipHideDelay = 2600;
		this.dictionary = "common.txt";

		// javascript is stupid
		this.handleEntryFieldChange = this.handleEntryFieldChange.bind(this);
		this.handleGenModeChange = this.handleGenModeChange.bind(this);
		this.handlePasswordLengthChange = this.handlePasswordLengthChange.bind(this);
		this.toggleUseSpecialChars = this.toggleUseSpecialChars.bind(this);
		this.handlePhraseLengthChange = this.handlePhraseLengthChange.bind(this);
		this.handle2faChange = this.handle2faChange.bind(this);
		this.handleGenPassword = this.handleGenPassword.bind(this);

		this.handleCopy = this.handleCopy.bind(this);
		this.handleCopyInner = this.handleCopyInner.bind(this);
		this.hideTooltip = this.hideTooltip.bind(this);

		this.handleSubmit = this.handleSubmit.bind(this);
		this.submitNewEntry = this.submitNewEntry.bind(this);
		this.submitExistingEntry = this.submitExistingEntry.bind(this);
		this.showHidePassword = this.showHidePassword.bind(this);
		this.showHideSettings = this.showHideSettings.bind(this);

		this.genCharset = this.genCharset.bind(this);

		this.charsets = {
			"special": this.genCharset(true),
			"alpha": this.genCharset(false)
		};
	}

	showHidePassword() {
		this.setState({
			isPasswordVisible: !this.state.isPasswordVisible
		});
	}

	showHideSettings() {
		this.setState({
			isSettingsVisible: !this.state.isSettingsVisible
		});
	}

	async submitExistingEntry() {
		const entry = {
			account: this.state.account,
			username: this.state.username,
			password: this.state.password,
			has_2fa: this.state.has_2fa,
			extra: this.state.extra
		};

		// zero out the server error message (if any)
		this.setState({
			errorMsg: null,
		});

		const r = await this.pzApi.updateEntry(this.state.id, entry, this.state.masterPassword);
		if(r.status === 200) {
			window.location.assign(`/entries/done_edit/${entry.account}`);
		} else {
			console.error(r.status);
			console.error(r);

			const j = await r.json();
			if (j.msg) {
				this.setState({
					errorMsg: j.msg,
				});
			}
		}
	}

	async submitNewEntry() {
		const entry = {
			account: this.state.account,
			username: this.state.username,
			password: this.state.password,
			has_2fa: this.state.has_2fa,
			extra: this.state.extra
		};

		// zero out the server error message (if any)
		this.setState({
			errorMsg: null,
		});

		const r = await this.pzApi.createEntry(entry, this.state.masterPassword);
		if(r.status === 200) {
			window.location.assign(`/entries/done_new/${entry.account}`);
		} else {
			console.error(r.status);
			console.error(r);

			const j = await r.json();
			if (j.msg) {
				this.setState({
					errorMsg: j.msg,
				});
			}
		}
	}

	handleSubmit(e: React.SyntheticEvent) {
		e.preventDefault();
		// note that both of the called functions are async
		if(this.state.isEntryNew) {
			this.submitNewEntry();
		} else {
			this.submitExistingEntry();
		}
		return false;
	}

	/**
	 * Handle changes for entry fields (text only)
	 */
	handleEntryFieldChange(event: React.ChangeEvent<HTMLInputElement | HTMLTextAreaElement>) {
		const val = event.target.value;
		const field = event.target.name;
		const formErrors = this.state.formErrors;

		const ENTRY_FIELDS = ['account', 'username', 'password', 'extra'];
		console.assert(ENTRY_FIELDS.includes(field));

		if (val.length > ENTRY_LIMITS[field]) {
			formErrors[field] = `${field} is too long`;
		} else {
			formErrors[field] = null;
		}

		this.setState({
			[field]: val,
			formErrors: formErrors,
		} as Pick<INewEntryState, any>);
	}

	handle2faChange(event) {
		this.setState({
			has_2fa: event.target.checked
		});
	}

	hideTooltip() {
		const now = new Date();
		const diff = now.valueOf() - (this.state.tooltipLastShown as Date).valueOf();
		if(diff >= this.tooltipHideDelay) {
			ReactTooltip.hide(this.copyTooltipRef.current);
			this.setState({
				isTooltipHidden: true,
			});
		} else {
			window.setTimeout(this.hideTooltip, diff);
		}
	}

	/**
	 * Note that you cannot copy a password field
	 * Therefore this method can only be called when the password is visible
	 */
	handleCopyInner() {
		this.passwordFieldRef.current.focus();
		this.passwordFieldRef.current.setSelectionRange(0, 9999);
		document.execCommand("copy");

		ReactTooltip.show(this.copyTooltipRef.current);
		this.setState({
			tooltipLastShown: new Date(),
			isTooltipHidden: false
		});
		window.setTimeout(this.hideTooltip, this.tooltipHideDelay);

		(event.target as HTMLButtonElement).focus();
	}

	/**
	 * Wrapper for copy, which neatly handles copying regardless of if the password is visible
	 */
	handleCopy(): void {
		// NOTE: copy does not work on password field directly, so have to create a hack
		if(!this.state.isPasswordVisible) {
			this.setState({
				isPasswordVisible: true
			}, () => {
				this.handleCopyInner();
				this.setState({
					isPasswordVisible: false
				})
			})
		} else {
			this.handleCopyInner();
		}
	}

	handleGenModeChange(newGenMode: string): void {
		this.setState({
			passwordGenMode: newGenMode
		});
	}

	handlePasswordLengthChange(length: number): void {
		this.setState({
			passwordLength: length
		});
	}

	toggleUseSpecialChars(): void {
		this.setState({
			useSpecialChars: !this.state.useSpecialChars
		});
	}

	handlePhraseLengthChange(length: number) {
		this.setState({
			numWords: length
		});
	}

	genCharset(useSpecialChars: boolean): string[] {
        const charset = [];
        for (let i = "a".charCodeAt(0); i <= "z".charCodeAt(0); i++) {
            charset.push(String.fromCharCode(i));
        }
        for (let i = "A".charCodeAt(0); i <= "Z".charCodeAt(0); i++) {
            charset.push(String.fromCharCode(i));
        }
        for (let i = "0".charCodeAt(0); i <= "9".charCodeAt(0); i++) {
            charset.push(String.fromCharCode(i));
        }
        if (useSpecialChars) {
            for (let i = "!".charCodeAt(0); i <= "/".charCodeAt(0); i++) {
                charset.push(String.fromCharCode(i));
            }
		}
		return charset;
	}

	/**
	 * Generate a random password from the character set
	 */
	genPassword(): string {
		const passArray: string[] = [];
		const charset = this.state.useSpecialChars ? this.charsets["special"] : this.charsets["ascii"];
		for(let i = 0; i < this.state.passwordLength; i++) {
			passArray[i] = charset[random(0, charset.length - 1, false)];
		}
		return passArray.join("");
	}

	/**
	 * Update the words in state
	 */
	async fetchDictionaryWords() {
		const r = await window.fetch("/dictionary/" + this.dictionary);
		if(r.status === 200) {
			const response = await r.text();
			const words = response.split("\n").filter((w: string) => {
				return w.length >= 5;
			});
			console.log(`Read ${words.length} words from dictionary`);
			return this.setState({
				words: words
			});
		} else {
			throw new Error("Failed to fetch dictionary");
		}
	}

	/**
	 * Words from dictionary loaded in componentDidMount
	 */
	genPhrase(): string {
        let phrase = "";
        for (let i = 0; i < this.state.numWords ; i++) {
            let word = this.state.words[random(0, this.state.numWords - 1, false)];
            word = word[0].toUpperCase() + word.substr(1);
            phrase += word;
        }
        return phrase;
	}

	handleGenPassword() {
		let pwd = "";
		if(this.state.passwordGenMode === "password") {
			pwd = this.genPassword();
		} else {
			pwd = this.genPhrase();
		}
		this.setState({
			password: pwd,
			isPasswordVisible: true
		});
	}

	componentDidMount() {
		// async
		this.fetchDictionaryWords();

		// load master password
		const masterPassword = (document.getElementById("master-password") as HTMLInputElement).value;

		// load user preferences
		const userPrefsEncoded = (document.getElementById("user-prefs") as HTMLInputElement).value;
		const userPrefs = JSON.parse(atob(userPrefsEncoded)) as IUserPrefs;

		this.setState({
			masterPassword: masterPassword,
			passwordLength: userPrefs.default_random_password_length,
			numWords: userPrefs.default_random_passphrase_length,
		}, () => {
			console.log("master password loaded");
			console.log("user password generation preferences loaded");
		});

		// determine if this is a new entry and the entryID if not
		const parts = window.location.href.split(/\//g);
		const entryId = Number.parseInt(parts[parts.length - 1]);
		if(isNaN(entryId)) {
			this.setState({
				isEntryNew: true
			});
		} else  {
			// load the data stored in serialized entry
			const serializedEntry = (document.getElementById("serialized-entry") as HTMLInputElement).value;
			const entry = JSON.parse(atob(serializedEntry));

			this.setState({
				isEntryNew: false,
				id: entryId,

				account: entry.account,
				username: entry.username,
				password: entry.password,
				extra: entry.extra || "",
				has_2fa: entry.has_2fa || false,
				version: entry.version
			});
		}
	}

	render() {
		let showHidePasswordBtn = null;
		if(this.state.password) {
			showHidePasswordBtn = (
				<button type="button"
					className="btn btn-info"
					onClick={this.showHidePassword}>
					{this.state.isPasswordVisible ? "Hide Password" : "Show Password"}
				</button>
			);
		}

		let settings = null;
		if(this.state.isSettingsVisible) {
			settings = (<Settings
				onGenModeChange={ this.handleGenModeChange}
				genMode={ this.state.passwordGenMode }
				onPasswordLengthChange={ this.handlePasswordLengthChange }
				passwordLength={ this.state.passwordLength }
				toggleUseSpecialChars={ this.toggleUseSpecialChars }
				useSpecialChars={ this.state.useSpecialChars }
				phraseLength={ this.state.numWords }
				onPhraseLengthChange={ this.handlePhraseLengthChange }
			></Settings>);
		}

		return (
			<form method="POST" role="form" onSubmit={ this.handleSubmit }>
				<h3 className="title">
					{ this.state.isEntryNew ? "Create New Entry" :  "Edit PassZero entry for " + this.state.account }
				</h3>

				{/* display the error message from server (if any) */}
				{ this.state.errorMsg ?
					<div className="alert alert-danger" role="alert">
						<strong>Error!</strong>&nbsp; {this.state.errorMsg}
					</div> :
					null }

				<div className="form-group">
					<label htmlFor="account">Account</label>
					<input type="text"
						name="account"
						required={ true }
						className={ classnames("form-control", {"is-invalid": this.state.formErrors.account}) }
						autoComplete="off"
						value={ this.state.account }
						onChange={ this.handleEntryFieldChange } />
					<div className="invalid-feedback">{ this.state.formErrors.account }</div>
				</div>

				<div className="form-group">
					<label htmlFor="username">Username</label>
					<input type="text"
						name="username"
						required={ true }
						className={ classnames("form-control", {"is-invalid": this.state.formErrors.username}) }
						autoComplete="email"
						value={ this.state.username }
						onChange={ this.handleEntryFieldChange } />
					<div className="invalid-feedback">{ this.state.formErrors.username }</div>
				</div>

				<div className="form-group">
					<label htmlFor="password">Password</label>
					<input type={ this.state.isPasswordVisible ? "text" : "password" }
						name="password"
						required={ true }
						id="password"
						className={ classnames("form-control", {"is-invalid": this.state.formErrors.password}) }
						autoComplete="off"
						ref={ this.passwordFieldRef }
						value={ this.state.password }
						onChange={ this.handleEntryFieldChange } />
					<div className="invalid-feedback">{ this.state.formErrors.password }</div>
				</div>

				<div className="btn-container">
					<ReactTooltip
						effect="solid"
						id={ `copy-tooltip-${this.state.id}`}></ReactTooltip>
					<button type="button"
						className="btn btn-success copy-pwd-btn"
						onClick={ this.handleCopy }
						ref={this.copyTooltipRef}
						data-tip="Copied"
						data-event="dblclick"
						data-for={ `copy-tooltip-${this.state.id}` }>
							Copy
					</button>
					<button type="button"
						className="btn btn-primary"
						onClick={this.handleGenPassword}>
						Random
					</button>
					{ showHidePasswordBtn }
					<button type="button"
						className="btn btn-settings"
						onClick={ this.showHideSettings }>
						<i className="fas fa-cog"></i> Settings
					</button>
				</div>

				{ settings }

				<div id="extra-container" className="form-group">
					<label htmlFor="extra">Extra</label>
					<textarea name="extra" id="extra" rows={4} cols={50}
						className={ classnames("form-control", {"is-invalid": this.state.formErrors.extra}) }
						value={ this.state.extra }
						onChange={ this.handleEntryFieldChange }></textarea>
					<div className="invalid-feedback">{ this.state.formErrors.extra }</div>
				</div>

				<div className="form-group">
					<input className="has-2fa-checkbox"
						type="checkbox"
						name="has_2fa"
						checked={ this.state.has_2fa }
						onChange={ this.handle2faChange } />
					<label htmlFor="has_2fa">2FA enabled</label>
				</div>

				<button type="submit" className="btn btn-success form-control"
					id="create-btn">
					{ this.state.isEntryNew ? "Create" : "Save" }
				</button>
			</form>
		);
	}
}

export default NewEntryApp;
