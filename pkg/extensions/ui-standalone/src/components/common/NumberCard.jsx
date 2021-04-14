import React from 'react';
import {Icon} from 'blueprint-react';
import PropTypes from 'prop-types';
import {HealthBadge} from '../widgets/summarypane/HealthBadge';
import './NumberCard.scss';

class NumberCard extends React.Component {
    render() {
        return (
            <div className="number-card-container" style={{width: this.props.width, height: this.props.height}}>
                <div className="number-card-value">{this.props.value}</div>
                <div className="number-card-label">{this.props.label}</div>
            </div>
        );
    }
}

NumberCard.propTypes = {
    width: PropTypes.string,
    value: PropTypes.oneOfType([PropTypes.string, PropTypes.number]),
    label: PropTypes.string,
    isHealthy: PropTypes.bool,
    height: PropTypes.string
};

NumberCard.defaultProps = {
    width: '96px',
    height: '80px',
    value: 0,
    label: '',
    isHealthy: false
};

export {NumberCard};
