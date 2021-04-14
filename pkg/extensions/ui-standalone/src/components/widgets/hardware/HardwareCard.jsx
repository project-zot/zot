import React from 'react';
import PropTypes from 'prop-types';
import {Loader} from 'blueprint-react';
import LABELS from '../../../strings';
import {NumberCard} from '../../common/NumberCard';

class HardwareCard extends React.Component {
    render() {
        const {fansObj, sensorsObj, psusObj, isLoading} = this.props;
        if (isLoading) {
            return <Loader />;
        }
        return (
            <div>
                <div className="number-cards-container">
                    <NumberCard value={fansObj.length} label={LABELS.fans} />
                    <NumberCard value={psusObj.length} label={LABELS.psu} />
                    <NumberCard value={sensorsObj.length} label={LABELS.sensors} />
                </div>
            </div>
        );
    }
}

HardwareCard.defaultProps = {
};

HardwareCard.propTypes = {
    obj: PropTypes.object,
    fansObj: PropTypes.any,
    sensorsObj: PropTypes.any,
    psusObj: PropTypes.any,
    isLoading: PropTypes.bool
};

export {HardwareCard};
