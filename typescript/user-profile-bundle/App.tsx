import { PureComponent } from "react";
import * as React from "react";
import PasszeroApiV3, { IUser } from "../common-modules/passzero-api-v3";

// instead of importing include it using a reference (since it's not a module)
// similarly for LogoutTimer variable
/// <reference path="../common/logoutTimer.ts" />

interface IAppState {
    user: IUser | null;
    isUsernameButtonPressed: boolean;
    usernameErrorMsg: string | null;
}

/**
 * Represents editing a new or existing link
 */
class App extends PureComponent<{}, IAppState> {
    logoutTimer: LogoutTimer;
    pzApi: PasszeroApiV3;

    constructor(props: any) {
        super(props);

        this.state = {
            user: null,
            isUsernameButtonPressed: false,
            usernameErrorMsg: null,
        };

        this.logoutTimer = new LogoutTimer();
        this.pzApi = new PasszeroApiV3();

        this.renderSetUsername = this.renderSetUsername.bind(this);
        this.handleSubmit = this.handleSubmit.bind(this);
    }

    componentDidMount() {
        this.pzApi.getCurrentUser().then((user: IUser) => {
            this.setState({
                user: user,
            });
        });
    }

    async handleSubmit(e: React.SyntheticEvent<HTMLFormElement>) {
        e.preventDefault();
        // reset error msg
        this.setState({
            usernameErrorMsg: null,
        });

        const username = (e.target as any).username.value;
        const response = await this.pzApi.updateCurrentUser({
            username,
        });
        if (response.status === 'success') {
            // just refresh when the username has been changed
            window.location.reload();
        } else {
            this.setState({
                usernameErrorMsg: response.msg,
            });
        }
        return false;
    }

    renderSetUsername() {
        if (!this.state.isUsernameButtonPressed) {
            const text = this.state.user.username ? 'change username': 'set username';
            return <button className="btn btn-info" onClick={ () => this.setState({
                isUsernameButtonPressed: true,
            })}>{ text }</button>
        } else {
            let labelClassName = 'col-sm-2 col-form-label';
            let inputClassName = 'form-control';
            if (this.state.usernameErrorMsg) {
                labelClassName += ' text-danger';
                inputClassName += ' is-invalid'
            }
            return <form role="form" id="changeUsernameForm" onSubmit={this.handleSubmit}>
                <div className="form-group">
                    <div className="row">
                        <label htmlFor="username" className={labelClassName}>username</label>
                        <div className="col-sm-7">
                            <input type="text" name="username" className={inputClassName} placeholder="your unique username"
                                required={true} minLength={2} maxLength={16} autoComplete="username" />
                        </div>
                    </div>
                    <div className="row">
                        { this.state.usernameErrorMsg
                            ? <small className="text-danger">{ this.state.usernameErrorMsg }</small>
                            : null }
                    </div>
                </div>
                <button type="submit" className="form-control btn-success">save username</button>
            </form>
        }
    }

    render() {
        if (!this.state.user) {
            // don't render anything
            return <div></div>;
        } else {
            return (<div>
                <h3 className="title">User Profile</h3>


                <table className="table table-sm table-borderless" id="readonly-user-details">
                    <tbody>
                        <tr>
                            <td className="table-info-cell">email</td>
                            <td>{ this.state.user.email }</td>
                        </tr>
                        <tr>
                            <td className="table-info-cell">last login</td>
                            <td>{ this.state.user.last_login }</td>
                        </tr>
                        { this.state.user.username
                            ? <tr>
                                <td className="table-info-cell">username</td>
                                <td>{ this.state.user.username }</td>
                            </tr>
                            : null }
                    </tbody>
                </table>

                { this.renderSetUsername() }
            </div>);
        }
    }
}

export default App;
