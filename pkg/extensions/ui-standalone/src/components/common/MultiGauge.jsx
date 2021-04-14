import React from 'react';
import PropTypes from 'prop-types';
import DonutChart from 'react-svg-donut-chart';
import './MultiGauge.scss';

class MultiGauge extends React.Component {
    constructor(props) {
        super(props);
    }

    render() {
        const {data, statusTotal} = this.props;
        const legends = [
            {color: '#e2231a', label: 'Pending Discovery', value: statusTotal.undiscovered + statusTotal.discovering || 0},
            {color: '#fbab18', label: 'Pending Registration', value: statusTotal.unknown || 0},
            {color: '#6cc04a', label: 'Active', value: statusTotal.Active || 0}
        ];

        const dataPie = [
            {stroke: '#e2231a', value: statusTotal.undiscovered + statusTotal.discovering || 0, strokeWidth: 3},
            {stroke: '#fbab18', value: statusTotal.unknown || 0, strokeWidth: 3},
            {stroke: '#6cc04a', value: statusTotal.Active || 0, strokeWidth: 3}
        ];
        return (
            <div className="multi-gauge-container">
                <div className="donut-chart-container">
                    <DonutChart data={dataPie} />
                    <div className="donut-chart-center">
                        <div>{data.length || 0}</div>
                    </div>
                </div>
                <div className="multi-gauge-legends-container">
                    {
                        legends.map(legend => {
                            return (
                                <div className={'legend legend-size'} key={legend.label}>
                                    <div className={'legend-indicator'} style={{backgroundColor: legend.color}} />
                                    <div className={'legend-label'}>
                                        {legend.label}
                                    </div>
                                    <div>{'(' + legend.value + ')'}</div>
                                </div>
                            );
                        })
                    }
                </div>
            </div>
        );
    }
}

MultiGauge.defaultProps = {
    data: []
};

MultiGauge.propTypes = {
    data: PropTypes.array,
    statusTotal: PropTypes.object
};

export {MultiGauge};
