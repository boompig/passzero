import * as React from 'react';
import Navbar from 'react-bootstrap/Navbar';
import Nav from 'react-bootstrap/Nav';
import Container from 'react-bootstrap/Container';
import { FontAwesomeIcon } from '@fortawesome/react-fontawesome';
import { library } from '@fortawesome/fontawesome-svg-core';
import { faList, faLink, faPlus, faUser, faWrench, faSignOutAlt } from '@fortawesome/free-solid-svg-icons';

import { clientSideLogout } from '../common-modules/client-side-utils';

// import "bootstrap/dist/css/bootstrap.min.css";

library.add(faList, faLink, faPlus, faUser, faWrench, faSignOutAlt);

interface INavbarItem {
    /**
     * The path to visit for this item
     */
    path: string;
    /**
     * Easy way for us to select a specific item
     */
    key: string;
    /**
     * The text displayed to the user
     */
    friendlyName: string;
    /**
     * The associated icon
     */
    icon?: React.ReactNode;

    /**
     * Instead of an href, instead perform this javascript action
     */
    onClick?(): void;
};

const navbarItems = [
    {
        path: '/entries',
        key: 'entries',
        friendlyName: 'Entries',
        icon: <FontAwesomeIcon icon={['fas', 'list']} />,
    },
    {
        path: '/entries/new',
        key: 'new-entry',
        friendlyName: 'New Entry',
        icon: <FontAwesomeIcon icon={['fas', 'plus']} />,
    },
    {
        path: '/links',
        key: 'links',
        friendlyName: 'Links',
        icon: <FontAwesomeIcon icon={['fas', 'link']} />,
    },
    {
        path: '/profile',
        key: 'profile',
        friendlyName: 'Profile',
        icon: <FontAwesomeIcon icon={['fas', 'user']} />,
    },
    {
        path: '/advanced',
        key: 'advanced',
        friendlyName: 'Advanced',
        icon: <FontAwesomeIcon icon={['fas', 'wrench']} />,
    },
    {
        path: '/logout',
        key: 'logout',
        friendlyName: 'Sign Out',
        icon: <FontAwesomeIcon icon={['fas', 'sign-out-alt']} />,
        onClick: (e: React.SyntheticEvent) => {
            e.preventDefault();
            clientSideLogout();
        },
    },
] as INavbarItem[];

export const LoggedInNavbar = () => {
    const currentPath = window.location.pathname;

    const navbarItemElems = navbarItems.map((item: INavbarItem) => {
        let classNames = 'navbar-item';
        let innerClassNames = 'nav-link';
        if (currentPath === item.path) {
            classNames += ' active';
            innerClassNames += ' active';
        }
        return <li className={classNames} key={item.key}>
            <a className={innerClassNames} href={item.path} onClick={item.onClick}>
                { item.icon? item.icon : null }
                <span className="nav-text">{ item.friendlyName }</span>
            </a>
        </li>;
    });

    return <Navbar className="navbar navbar-dark bg-primary fixed-top navbar-expand-lg" expand="md" id="logged-in-navbar">
        <Container fluid>
            <Navbar.Brand className="navbar-brand" href="/">PassZero</Navbar.Brand>
            <Navbar.Toggle aria-controls="about-navbar-nav" />

            <Navbar.Collapse id="about-navbar-nav" role="navigation">
                <Nav className="navbar-nav ml-auto justify-content-end">
                    { navbarItemElems }
                </Nav>
            </Navbar.Collapse>
        </Container>
    </Navbar>;
};

export default LoggedInNavbar;
