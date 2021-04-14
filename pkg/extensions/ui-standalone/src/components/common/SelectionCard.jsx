import PropTypes from 'prop-types';
import React from 'react';
import {Radio} from 'blueprint-react';
import classnames from 'classnames';

import styles from './SelectionCard.scss';

const SelectionCard = ({label, description, isSelected, isDisabled, onClick, icon}) => {
    const cardClasses = ['selectionCard'];
    if (isSelected) {
        cardClasses.push('isSelected');
    }

    return (
        <div className={cardClasses.join(' ')} onClick={onClick}>
            <div className="selectioncard-header">
                <Radio key={label} value={isSelected} checked={isSelected} disabled={isDisabled} />
            </div>
            <div className="selectioncard-content">
                {icon || null}
                <div className="selectioncard-label">{label}</div>
                <div>{description}</div>
            </div>
        </div>
    );
};

SelectionCard.propTypes = {
    label: PropTypes.string,
    isSelected: PropTypes.bool,
    description: PropTypes.string,
    isDisabled: PropTypes.bool,
    onClick: PropTypes.func,
    icon: PropTypes.node,
};

export default SelectionCard;
