import * as React from "react";
import Navbar from 'react-bootstrap/Navbar';
import Nav from 'react-bootstrap/Nav';
import Container from 'react-bootstrap/Container';
import { FontAwesomeIcon } from '@fortawesome/react-fontawesome';
import { library } from '@fortawesome/fontawesome-svg-core';
import { faList, faLink, faFileArchive, faPlus, faFileUpload, faUser, faWrench, faSignOutAlt } from '@fortawesome/free-solid-svg-icons';

// import "bootstrap/dist/css/bootstrap.min.css";

library.add(faList, faLink, faFileArchive, faPlus, faFileUpload, faUser, faWrench, faSignOutAlt);

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
};

const navbarItems = [
    {
        path: "/entries",
        key: "entries",
        friendlyName: "Entries",
        icon: <FontAwesomeIcon icon={["fas", "list"]} />,
    },
    {
        path: "/entries/new",
        key: "new-entry",
        friendlyName: "New Entry",
		icon: <FontAwesomeIcon icon={["fas", "plus"]} />,
    },
    {
        path: "/links",
        key: "links",
        friendlyName: "Links",
        icon: <FontAwesomeIcon icon={["fas", "link"]} />,
    },
    // {
    //     path: "/docs",
    //     key: "docs",
    //     friendlyName: "Documents",
    //     icon: <FontAwesomeIcon icon={["fas", "file-archive"]} />,
    // },
    // {
    //     path: "/docs/new",
    //     key: "new-doc",
    //     friendlyName: "New Document",
    //     icon: <FontAwesomeIcon icon={["fas", "file-upload"]} />,
    // },
    {
        path: "/profile",
        key: "profile",
        friendlyName: "Profile",
        icon: <FontAwesomeIcon icon={["fas", "user"]} />,
    },
    {
        path: "/advanced",
        key: "advanced",
        friendlyName: "Advanced",
        icon: <FontAwesomeIcon icon={["fas", "wrench"]} />,
    },
    {
        path: "/logout",
        key: "logout",
        friendlyName: "Sign Out",
        icon: <FontAwesomeIcon icon={["fas", "sign-out-alt"]} />,
    },
] as INavbarItem[];

export const LoggedInNavbar = () => {
    const navbarItemElems = navbarItems.map((item: INavbarItem) => {
        let classNames = 'navbar-item';
        if (item.key === 'about') {
            classNames += ' active';
        }
        return <li className={classNames} key={item.key}>
            <a className="nav-link" href={item.path}>
                { item.icon? item.icon : null }
                <span className="nav-text">{ item.friendlyName }</span>
            </a>
        </li>
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