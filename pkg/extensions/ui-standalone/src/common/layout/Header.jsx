import React from 'react';
import PropTypes from 'prop-types';

import {IconButton, Dropdown, Icon, Button} from 'blueprint-react';

import LABELS from '../../strings';

import './Header.css';

class Header extends React.Component {
    constructor(props) {
        super(props);
        this.state = {
            searchValue: '',
            enableSearhIcon: false,
            version: ''
        };

        // Build the User menu
        this.userItems = [];
        this.userItems.push(
            {label: 'Welcome'},
            {
                action: () => {
                },
                label: LABELS.logOut
            }
        );
    }

    componentDidMount() {

    }

    helpItems = [
        {
            action: () => {
            },
            label: LABELS.aboutZot
        },
    ];

    gearItems = [
        {
            action: () => {

            },
            label: LABELS.changePassword
        }

    ];

    render() {
        let headerBtns = (
            <div className="header-buttons">
                <div style={{paddingLeft: '5px'}}>
                    <Dropdown type={Dropdown.TYPE.BUTTON} size={IconButton.SIZE.SMALL} icon={IconButton.ICON.COG} menuDirection={Dropdown.MENU_DIRECTION.LEFT} items={this.gearItems} />
                </div>
                <div style={{paddingLeft: '5px'}}>
                    <Dropdown type={Dropdown.TYPE.BUTTON} size={IconButton.SIZE.SMALL} icon={IconButton.ICON.HELP} menuDirection={Dropdown.MENU_DIRECTION.LEFT} items={this.helpItems} />
                </div>

                <div className="header-dropdown-user">
                    <Dropdown theme={Button.TYPE.SECONDARY} type={Dropdown.TYPE.BUTTON} size={IconButton.SIZE.LARGE} icon={Icon.TYPE.USER} menuDirection={Dropdown.MENU_DIRECTION.LEFT} items={this.userItems} />
                </div>
            </div>
        );

        return (
            <div>
                <header className="global-header">
                    <div className="header-bar__logo">
                        <span className="icon-cisco" />
                    </div>
                    <div className="app-title">
                        <h4>{LABELS.zotHub}</h4>
                    </div>
                    {headerBtns}
                </header>
            </div>
        );
    }
}

Header.propTypes = {
};

export {Header};
