import React from 'react';
import PropTypes from 'prop-types';
import {WidgetPanel} from '../panel/WidgetPanel';
import './SkeletonWidgetPanel.scss';

class SkeletonWidgetPanel extends React.Component {
    renderFakeProperties() {
        let list = [];
        for (let i = 0; i < this.props.properties; i++) {
            list.push(
                <li className={this.props.twoColumns ? 'col-6' : ''} key={i}>
                    <div className="fake-label" />
                    <div className="fake-property-value" />
                </li>
            );
        }
        return list;
    }

    render() {
        return (
            <WidgetPanel className="skeleton">
                <ul className={'list' + (this.props.twoColumns ? ' row' : '')}>{this.renderFakeProperties()}</ul>
            </WidgetPanel>
        );
    }
}

SkeletonWidgetPanel.propTypes = {
    properties: PropTypes.any,
    twoColumns: PropTypes.any,
};

SkeletonWidgetPanel.defaultProps = {
    properties: 2,
    twoColumns: false,
};

export {SkeletonWidgetPanel};
