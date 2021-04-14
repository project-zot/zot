import React from 'react';
import {filter} from 'lodash';
import PropTypes from 'prop-types';
import {SummaryProgress} from '../../../pages/dashboard/SummaryProgress';
import LABELS from '../../../strings';

class HardwareUsageStorage extends React.Component {
    totalStorage = (data) => {
        let usedSpace = 0;
        let filterData = filter(data, ['fstype', 'ext2/ext3']);
        filterData.map((arr) => {
            usedSpace = usedSpace + arr.usedPercent;
        });
        usedSpace = usedSpace / filterData.length;
        return usedSpace;
    }

    render() {
        const {dataProp} = this.props;
        const percentage = this.totalStorage(dataProp) || 0;
        return (
            <SummaryProgress percent={percentage.toFixed(2)} label={LABELS.storage}/>
        );
    }
}

HardwareUsageStorage.propTypes = {
    dataProp: PropTypes.array
};

export {HardwareUsageStorage};
