import React from 'react';
import _ from 'lodash';
import PropTypes from 'prop-types';

class DetailsScreenTab extends React.Component {
    componentDidMount() {
        if (typeof this.props.refreshTrigger === 'function') {
            this.props.refreshTrigger(this.props.onRefresh);
        }
    }

    render() {
        return this.props.children;
    }
}

DetailsScreenTab.defaultProps = {
    onRefresh: _.noop
};

DetailsScreenTab.propTypes = {
    refreshTrigger: PropTypes.func,
    onRefresh: PropTypes.func,
    children: PropTypes.node
};
export {DetailsScreenTab};
