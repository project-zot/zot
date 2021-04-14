import React from 'react';
import PropTypes from 'prop-types';
import './WidgetPanel.scss';

class WidgetPanel extends React.Component {
    constructor(props) {
        super(props);
        this.state = {
            collapsed: this.props.collapsed
        };
    }

    toggleCollapse = () => {
        if (this.props.collapsible) {
            this.setState({collapsed: !this.state.collapsed});
        }
    };

    renderCollapseIcon() {
        if (!this.props.collapsible) {
            return null;
        }
        if (this.state.collapsed) {
            return (
                <span className="link icon-chevron-down icon-small"/>
            );
        }
        return (
            <span className="link icon-chevron-up icon-small"/>
        );
    }

    renderPopOutIcon() {
        if (!this.props.popOutAction) {
            return null;
        }
        return (
            <span className="link icon-jump-out icon-small" onClick={this.props.popOutAction}/>
        );
    }

    renderEditIcon() {
        if (!this.props.openEditAction) {
            return null;
        }
        return (
            <span className="link icon-edit icon-small" onClick={this.props.openEditAction}/>
        );
    }

    renderDeleteIcon() {
        if (!this.props.openDeleteAction) {
            return null;
        }
        return (
            <span className="link icon-trash icon-small" onClick={this.props.openDeleteAction}/>
        );
    }

    renderMain() {
        if (this.state.collapsed) {
            return null;
        }

        return (
            <div className="main-content">
                {this.props.children}
            </div>
        );
    }

    render() {
        const {className, title, headerTool} = this.props;
        const classes = ['widget-panel', 'panel--bordered', className];

        if (this.props.collapsible) {
            classes.push('collapsible');
        }

        return (
            <div className={classes.join(' ')}>
                <header onClick={this.toggleCollapse}>
                    <span className="title">{title}</span>
                    {this.renderPopOutIcon()}
                    {this.renderCollapseIcon()}
                    {this.renderEditIcon()}
                    {this.renderDeleteIcon()}
                    {headerTool ? headerTool : null}
                </header>
                {this.renderMain()}
            </div>
        );
    }
}

WidgetPanel.defaultProps = {
    collapsible: false,
    collapsed: false
};

WidgetPanel.propTypes = {
    collapsible: PropTypes.bool,
    collapsed: PropTypes.bool,
    popOutAction: PropTypes.func,
    openEditAction: PropTypes.func,
    openDeleteAction: PropTypes.func,
    children: PropTypes.node,
    className: PropTypes.string,
    title: PropTypes.string,
    headerTool: PropTypes.object
};

export {WidgetPanel};
