import React from 'react';
import _ from 'lodash';
import PropTypes from 'prop-types';
import {Property} from './Property';
import {PropertyLabel} from './PropertyLabel';

import './PropertyListItem.scss';

const EMPTY_PLACEHOLDER = '-';
class PropertyListItem extends React.Component {
    render() {
        const {obj = {}, property, label, value, className, children, mandatory} = this.props;
        const propDescriptor = _.get(obj, `_classDescriptor[${property}]`);
        const val = value || obj[property] || EMPTY_PLACEHOLDER;

        if (typeof children !== 'undefined') {
            return (
                <li key={property} className={'property-list-item ' + className}>
                    <PropertyLabel className="property-label" label={label} mandatory={mandatory}/>
                    {children}
                </li>
            );
        }

        // if the object does not have this property just skip it
        if (typeof propDescriptor === 'undefined' && typeof value === 'undefined') {
            return null;
        }

        return (
            <li key={property} className={'property-list-item ' + className}>
                <PropertyLabel className="property-label" moClass={obj.class} label={label} property={property}/>
                <div className="property-value"><Property propDescriptor={propDescriptor} value={val}/></div>
            </li>
        );
    }
}

PropertyListItem.defaultProps = {
    className: ''
};

PropertyListItem.propTypes = {
    obj: PropTypes.any,
    property: PropTypes.string,
    label: PropTypes.string,
    value: PropTypes.string,
    className: PropTypes.string,
    children: PropTypes.node,
    mandatory: PropTypes.bool
};

export {PropertyListItem};
