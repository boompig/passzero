/**
 * This component manages the search functionality
 */

import { Component } from 'react';
import * as React from 'react';
import { FontAwesomeIcon } from '@fortawesome/react-fontawesome';
import { library } from '@fortawesome/fontawesome-svg-core';
import { faSearch } from '@fortawesome/free-solid-svg-icons';

library.add(faSearch);

interface ISearchFormProps {
    onSearch(searchString: string): void;
}

interface ISearchFormState {
    searchText: string;
}

/**
 * The search component for looking through entries.
 */
export default class SearchForm extends Component<ISearchFormProps, ISearchFormState> {
    constructor(props: ISearchFormProps) {
        super(props);

        this.state = {
            searchText: '',
        };

        this.handleChange = this.handleChange.bind(this);
        this.handleSubmit = this.handleSubmit.bind(this);
    }

    handleChange(event: React.SyntheticEvent): void {
        this.props.onSearch((event.target as HTMLInputElement).value);
    }

    /**
     * Prevent the search form from being submitted - we're only interested in capturing the change event
     */
    handleSubmit(e) {
        e.preventDefault();
        return false;
    }

    render() {
        return (
            <form id="search-form" onSubmit={this.handleSubmit}>
                <div className="input-group">
                    <input type="text" name="search" id="search"
                        className="form-control"
                        placeholder="search"
                        autoFocus={ true }
                        onChange={ this.handleChange } />
                    <span className="input-group-text">
                        <FontAwesomeIcon icon={['fas', 'search']} />
                    </span>
                </div>
            </form>
        );
    }
}
