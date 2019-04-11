/**
 * This component displays the number of entries that this user has
 */

import {Component} from "react";
import * as React from "react";

interface INumEntriesProps {
    entriesLoaded: boolean;
    numEntries: number;
}

interface INumEntriesState {}

/**
 * When entriesLoaded is false, value of numEntries does not matter
 */
export default class NumEntries extends Component<INumEntriesProps, INumEntriesState> {
    render() {
        let innerTitle = null;
        if (this.props.entriesLoaded) {
            if (this.props.numEntries === 1) {
                innerTitle = "You have 1 entry";
            } else if (this.props.numEntries === 0) {
                // filled in later below
            } else {
                innerTitle = `You have ${this.props.numEntries} entries`;
            }
        } else {
            innerTitle = "Loading entries...";
        }

        if (this.props.entriesLoaded && this.props.numEntries === 0) {
            // handled seperately
            return (
                <div id="num-entries">
                    <div className="empty-msg">
                        No entries yet. Try <a href="/entries/new">making some</a>.
                    </div>
                </div>
            );
        } else {
            return (
                <div id="num-entries">
                    <h2 className="title">{ innerTitle }</h2>
                </div>
            );
        }
    }
}
