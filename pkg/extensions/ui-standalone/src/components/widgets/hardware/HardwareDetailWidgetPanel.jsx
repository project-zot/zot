import React from 'react';
import PropTypes from 'prop-types';
import {isEmpty} from 'lodash';
import {WidgetPanel} from '../panel/WidgetPanel';
import {PropertyListItem} from '../../common/PropertyListItem';
import LABELS from '../../../strings';

class HardwareDetailWidgetPanel extends React.Component {
    render() {
        const {obj: {usage, duration = '-'}} = this.props;
        let cpuUsage = '-';
        if (usage) {
            cpuUsage = usage.toFixed(2);
        }
        return (
            <WidgetPanel title={LABELS.hardwareDetails}>
                <ul className={'list row'}>
                    <PropertyListItem className="col-sm-6" label={LABELS.cpuUsage} value={cpuUsage} />
                    <PropertyListItem className="col-sm-6" label={LABELS.duration} value={duration} />
                </ul>
            </WidgetPanel>
        );
    }
}

HardwareDetailWidgetPanel.defaultProps = {
};

HardwareDetailWidgetPanel.propTypes = {
    obj: PropTypes.array
};

export {HardwareDetailWidgetPanel};
