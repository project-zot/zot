import React from 'react';
import PropTypes from 'prop-types';

import {WidgetPanel} from '../panel/WidgetPanel';
import {HardwareCard} from './HardwareCard';

import api from '../../../common/utils/api';
import {URL} from '../../../constants';
import LABELS from '../../../strings';
import {regexes} from '../../../common/utils/validation-utils.js';

class HardwareWidgetPanel extends React.Component {
    constructor() {
        super();
        this.state = {
            isLoading: false,
            fansObj: [],
            sensorsObj: [],
            psusObj: []
        };
    }

    componentDidMount() {
        const {obj: {status}} = this.props;
        if (status === 'Active') {
            Promise.all([
                this.hardwareResourseFans(),
                this.hardwareResourseSensors(),
                this.hardwareResoursePsus()
            ]);
        }
    }

    hardwareResourseFans = () => {
        this.hardwareResourseUtil('/fans')
            .then((response) => {
                this.setState({fansObj: response.data, isLoading: false});
            })
            .catch(() => {
                this.setState({isLoading: false});
            });
    }

    hardwareResourseSensors = () => {
        this.hardwareResourseUtil('/sensors')
            .then((response) => {
                this.setState({sensorsObj: response.data, isLoading: false});
            })
            .catch(() => {
                this.setState({isLoading: false});
            });
    }

    hardwareResoursePsus = () => {
        this.hardwareResourseUtil('/psus')
            .then((response) => {
                this.setState({psusObj: response.data, isLoading: false});
            })
            .catch(() => {
                this.setState({isLoading: false});
            });
    }

    hardwareResourseUtil = (param) => {
        this.setState({isLoading: true});
        const {obj: {inbandIP}} = this.props;
        let url = URL.hardwareResource + inbandIP.replace(regexes.RE_SUBNET_STRING, '') + param;
        return api.get(url);
    }

    render() {
        const {fansObj, sensorsObj, psusObj, isLoading} = this.state;
        return (
            <WidgetPanel title={LABELS.hardwareResources}>
                <HardwareCard fansObj={fansObj} sensorsObj={sensorsObj} psusObj={psusObj} isLoading={isLoading} />
            </WidgetPanel>
        );
    }
}

HardwareWidgetPanel.defaultProps = {
};

HardwareWidgetPanel.propTypes = {
    obj: PropTypes.object
};

export {HardwareWidgetPanel};
