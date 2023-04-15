import * as React from 'react';
import Navbar from 'react-bootstrap/Navbar';
import Nav from 'react-bootstrap/Nav';
import Container from 'react-bootstrap/Container';
import { FontAwesomeIcon } from '@fortawesome/react-fontawesome';
import { library } from '@fortawesome/fontawesome-svg-core';
import { faHome } from '@fortawesome/free-solid-svg-icons/faHome';
import { faInfoCircle } from '@fortawesome/free-solid-svg-icons/faInfoCircle';
import { faSignInAlt } from '@fortawesome/free-solid-svg-icons/faSignInAlt';
import { faEdit } from '@fortawesome/free-solid-svg-icons/faEdit';

import './AboutNavbar.css';

library.add(faHome, faInfoCircle, faSignInAlt, faEdit);

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
    icon: React.ReactNode;
};

const navbarItems = [
    {
        path: '/',
        key: 'index',
        friendlyName: 'Home',
        icon: <FontAwesomeIcon icon={['fas', 'home']} />,
    },
    {
        path: '/about',
        key: 'about',
        friendlyName: 'About',
        icon: <FontAwesomeIcon icon={['fas', 'info-circle']} />,
    },
    {
        path: '/login',
        key: 'login',
        friendlyName: 'Sign In',
        icon: <FontAwesomeIcon icon={['fas', 'sign-in-alt']} />,
    },
    {
        path: '/signup',
        key: 'register',
        friendlyName: 'Register',
        icon: <FontAwesomeIcon icon={['fas', 'edit']} />,
    },
] as INavbarItem[];

/**
 * This is a bootstrap navbar that is only active on the About page
 */
export const AboutNavbar = () => {
    const currentPath = window.location.pathname;
    const navbarItemElems = navbarItems.map((item) => {
        let classNames = 'navbar-item';
        let innerClassNames = 'nav-link';
        if (currentPath === item.path) {
            classNames += ' active';
            innerClassNames += ' active';
        }
        return <li className={classNames} key={item.key}>
            <a className={innerClassNames} href={item.path}>
                { item.icon }
                <span className="nav-text">{ item.friendlyName }</span>
            </a>
        </li>;
    });

    return <Navbar className="navbar navbar-dark bg-primary fixed-top navbar-expand-lg" expand="md" id="about-navbar">
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

export default AboutNavbar;
