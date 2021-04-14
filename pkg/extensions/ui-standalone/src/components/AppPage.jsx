// react global
import React from 'react';
import PropTypes from 'prop-types';

// components
import {Dropdown} from 'blueprint-react';
import {IconButton, Button} from 'blueprint-react';

// utility
import LABELS from '../strings';
import {isEmpty, noop} from 'lodash';

// styling
import './AppPage.scss';

class AppPage extends React.Component {
    render() {
        const {title = '', onRefresh, actionsMenuItems, actionButtons = []} = this.props;
        let buttons = actionButtons.map((actionButton, index) => {
            return (<Button key={index} size={actionButton.size || Button.SIZE.SMALL} type={actionButton.type || Button.TYPE.PRIMARY} onClick={actionButton.onClick || noop} disabled={actionButton.disabled}>{actionButton.label}</Button>);
        });
        let header = null;
        const titleCls = title.replace(/\s+/g, '-').toLowerCase();
        if (title || !isEmpty(actionsMenuItems) || typeof onRefresh !== 'undefined') {
            header = (
                <header>
                    <div className="title">
                        <h2>{title}</h2>
                    </div>
                    <div className="right-menu">
                        {buttons}
                        {typeof onRefresh !== 'undefined' ? <IconButton size={IconButton.SIZE.SMALL} icon={IconButton.ICON.REFRESH} onClick={onRefresh}/> : null}
                        {isEmpty(actionsMenuItems) ?
                            null :
                            <Dropdown
                                key={'action'}
                                type={Dropdown.TYPE.BUTTON}
                                theme={Button.TYPE.SECONDARY}
                                size={Button.SIZE.SMALL}
                                label={LABELS.actions}
                                menuDirection={Dropdown.MENU_DIRECTION.LEFT}
                                items={actionsMenuItems}
                            />
                        }
                    </div>
                </header>
            );
        }
        return (
            <div className={`app-page ${titleCls}`}>
                {header}
                <main className="app-main-pad">
                    {this.props.children}
                </main>
            </div>
        );
    }
}

AppPage.defaultProps = {
    actionsMenuItems: []
};

AppPage.propTypes = {
    title: PropTypes.string,
    onRefresh: PropTypes.func,
    actionsMenuItems: PropTypes.any,
    actionButtons: PropTypes.array,
    children: PropTypes.node
};

export {AppPage};
