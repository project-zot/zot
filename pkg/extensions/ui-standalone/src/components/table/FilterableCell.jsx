import React from 'react';
import PropTypes from 'prop-types';
import {Icon} from 'blueprint-react';
import _ from 'lodash';

export default class FilterableCell extends React.Component {
    render() {
        const {property, row = {}, cell, onClick, ...rest} = this.props;
        let content = row.value;
        if (typeof cell === 'function') {
            content = cell(row);
        }
        return (
            <React.Fragment>
                <div className="cell-content">
                    {content}
                </div>
                <Icon className="hover-filter-icon" type={Icon.TYPE.FILTER} size={Icon.SIZE.SMALL} onClick={this.onClick} {...rest}/>
            </React.Fragment>
        );
    }

    onClick = (event) => {
        if (typeof this.props.onClick === 'function') {
            event.stopPropagation();
            const {property, row = {}} = this.props;
            this.props.onClick(property, row.value);
        }
    }
}

FilterableCell.defaultProps = {
    onClick: _.noop
};

FilterableCell.propTypes = {
    property: PropTypes.any,
    row: PropTypes.any,
    cell: PropTypes.any,
    onClick: PropTypes.func
};
