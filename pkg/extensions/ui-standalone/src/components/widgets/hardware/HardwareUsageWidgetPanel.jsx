import React from 'react';
import PropTypes from 'prop-types';

import {WidgetPanel} from '../panel/WidgetPanel';
import {Gauge} from '../../../components/charts/Gauge';
import {HardwareUsageStorage} from './HardwareUsageStorage';
import {PropertyListItem} from '../../../components/common/PropertyListItem';
import {cumulative} from '../../../common/utils/validation-utils';
import api from '../../../common/utils/api';
import {URL} from '../../../constants';
import LABELS from '../../../strings';
import {regexes} from '../../../common/utils/validation-utils.js';

class HardwareUsageWidgetPanel extends React.Component {
    constructor() {
        super();
        this.state = {
            isLoading: false,
            memoryObj: [],
            storageObj: [],
            cpuObj: []
        };
    }

    componentDidMount() {
        const {obj: {status}} = this.props;
        if (status === 'Active') {
            this.fetchApi();
        }
    }

    componentDidUpdate(prevProps) {
        // TO refresh pages
        if (this.props.pageReload !== prevProps.pageReload) {
            const {obj: {status}} = this.props;
            if (status === 'Active') {
                this.fetchApi();
            }
        }
    }

    fetchApi = () => {
        this.setState({isLoading: true});
        Promise.all([
            this.hardwareResourseMemory(),
            this.hardwareResourseStorage(),
            this.hardwareResourseCpu()
        ]);
    }

    hardwareResourseMemory = () => {
        this.hardwareResourseUtil('/memory')
            .then((response) => {
                this.setState({memoryObj: response.data, isLoading: false});
            })
            .catch(() => {
                this.setState({memoryObj: [], isLoading: true});
            });
    }

    hardwareResourseStorage = () => {
        this.hardwareResourseUtil('/mountstats')
            .then((response) => {
                this.setState({storageObj: response.data, isLoading: false});
            })
            .catch(() => {
                this.setState({storageObj: [], isLoading: true});
            });
    }

    hardwareResourseCpu = () => {
        this.hardwareResourseUtil('/cpuusage')
            .then((response) => {
                this.setState({cpuObj: response.data, isLoading: false});
            })
            .catch(() => {
                this.setState({cpuObj: [], isLoading: true});
            });
    }

    hardwareResourseUtil = (param) => {
        const {obj: {inbandIP}} = this.props;
        let url = URL.hardwareResource + inbandIP.replace(regexes.RE_SUBNET_STRING, '') + param;
        return api.get(url);
    }

    render() {
        const {nodeUtility: {cpuRequests = 0, cpuLimits = 0, cpuCapacity = 0, memoryCapacity = 0, memoryRequests = 0, memoryLimits = 0}} = this.props;
        const {storageObj, memoryObj, cpuObj} = this.state;
        const memoryPercent = memoryObj.usedPercent || 0;
        const cpuPercent = cpuObj.usage || 0;
        return (
            <WidgetPanel title={LABELS.hardwareUsage}>
                <div className="list row">
                    <div className="col-sm-6">
                        <Gauge size={Gauge.SIZE.SMALL} type={Gauge.TYPE.INFO} label={'CPU Usage'} data1={{value: cpuPercent.toFixed(2)}} />
                    </div>
                    <div className="col-sm-6">
                        <Gauge size={Gauge.SIZE.SMALL} type={Gauge.TYPE.INFO} label={LABELS.memory} data1={{value: memoryPercent.toFixed(2)}} />
                    </div>
                    <div className="col-sm-10" style={{padding: '25px 0px 20px 60px'}}>
                        <HardwareUsageStorage dataProp={storageObj} />
                    </div>
                    <PropertyListItem className="col-sm-6" label={'CPU Requests'} value={cumulative(cpuRequests, cpuCapacity)} />
                    <PropertyListItem className="col-sm-6" label={'CPU Limits'} value={cumulative(cpuLimits, cpuCapacity)} />
                    <PropertyListItem className="col-sm-6" label={'CPU Capacity'} value={String(cpuCapacity)} />
                    <PropertyListItem className="col-sm-6" label={'Memory Capacity'} value={String(memoryCapacity)} />
                    <PropertyListItem className="col-sm-6" label={'Memory Limits'} value={cumulative(memoryLimits, memoryCapacity)} />
                    <PropertyListItem className="col-sm-6" label={'Memory Requests'} value={cumulative(memoryRequests, memoryCapacity)} />

                </div>
            </WidgetPanel>
        );
    }
}

HardwareUsageWidgetPanel.defaultProps = {
};

HardwareUsageWidgetPanel.propTypes = {
    obj: PropTypes.object,
    pageReload: PropTypes.number,
    nodeUtility: PropTypes.oneOfType([PropTypes.object, PropTypes.array])
};

export {HardwareUsageWidgetPanel};
