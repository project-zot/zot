import React from 'react';
import PropTypes from 'prop-types';
import _ from 'lodash';

import './TotalCount.scss';

const TotalCount = (props) => {
    const {count, text} = props;
    return (
        <div className="total__count">
            <div className="count">{count}</div>
            <div className="text">{text}</div>
        </div>
    );
};

TotalCount.propTypes = {
    count: PropTypes.number,
    text: PropTypes.string,
};

export {TotalCount};
