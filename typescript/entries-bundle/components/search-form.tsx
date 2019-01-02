/**
 * This component manages the search functionality
 */

import {Component} from 'react';
import * as React from 'react';

interface ISearchFormProps {
    onSearch(searchString: string): void;
}

interface ISearchFormState {
    searchText: string;
}

export default class SearchForm extends Component<ISearchFormProps, ISearchFormState> {
    constructor(props: ISearchFormProps) {
        super(props);

        this.state = {
            searchText: '',
        };

        this.handleChange = this.handleChange.bind(this);
    }

    handleChange(event: React.SyntheticEvent): void {
        this.props.onSearch((event.target as HTMLInputElement).value);
    }

    render() {
        return (
            <form id='search-form'>
                <div className='input-group'>
                    <input type='text' name='search' id='search'
                        className='form-control'
                        placeholder='search'
                        autoFocus={ true }
                        onChange={ this.handleChange } />
                    <div className='input-group-append'>
                        <span className='input-group-text'>
                            <i className='fas fa-search'></i>
                        </span>
                    </div>
                </div>
            </form>
        );
    }
}