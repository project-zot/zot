import React from 'react';
import PropTypes from 'prop-types';
import {PieChart as Chart, Pie, Sector, Cell} from 'recharts';
import {TitledTooltip} from 'blueprint-react';

import {TotalCount} from './TotalCount';
import {RANDOM_COLORS} from '../../constants';

import './PieChart.scss';
import {filter, isEmpty} from 'lodash';

const SIZES = {
    SMALL: 'small',
    DEFAULT: 'default',
    LARGE: 'large'
};
const SIZES_CONFIG = {
    [SIZES.LARGE]: {
        width: 140,
        height: 150,
        centerX: 60,
        centerY: 80,
        innerRadius: 55,
        outerRadius: 60,
        countFontSize: 32,
        countTextFontSize: 14
    },
    [SIZES.DEFAULT]: {
        width: 130,
        height: 130,
        centerX: 60,
        centerY: 60,
        innerRadius: 55,
        outerRadius: 60,
        countFontSize: 32,
        countTextFontSize: 14
    },
    [SIZES.SMALL]: {
        width: 78,
        height: 78,
        centerX: 35,
        centerY: 35,
        innerRadius: 32,
        outerRadius: 35,
        countFontSize: 24,
        countTextFontSize: 8
    }
};

class PieChart extends React.Component {
    constructor(props) {
        super(props);
        this.state = {
            totalSum: 0,
            activeIndex: 0,
            countText: '',
            percentageText: false
        };
        this.colors = [];
    }

    componentDidMount() {
        this.prepareData(this.props);
    }

    componentWillReceiveProps(nextProps) {
        this.prepareData(nextProps);
    }

    prepareData(props) {
        let colors = props.colors || [];
        const data = props.data || [];
        const countText = props.countText;
        const percentageText = props.percentageText;
        let randomColorIdx = 0;

        if (isEmpty(colors)) {
            // if colors are not specified in the props, look for the color specified in the data
            if (!isEmpty(data)) {
                colors = data.map((count) => count.color || RANDOM_COLORS[randomColorIdx++ % RANDOM_COLORS.length]);
            } else {
                colors = [...RANDOM_COLORS];
            }
        }
        this.colors = [...colors];

        let maxVal = 0;
        let activeIndex = 0;
        let totalSum = 0;
        let fill = '#000000';

        data.forEach((item, i) => {
            const currentVal = parseInt(item.value, 10);
            if (currentVal > maxVal) {
                maxVal = currentVal;
                activeIndex = i;
            }
            totalSum = totalSum + currentVal;
        });

        if (colors && colors.length) {
            fill = colors[activeIndex];
        }

        this.setState({
            totalSum: totalSum,
            activeIndex: activeIndex,
            countText: countText,
            percentageText: percentageText,
            fill: fill
        });
    }

    renderActiveShape = (props) => {
        const {cx, cy, innerRadius, outerRadius, startAngle, endAngle} = props;
        let countTextY = cy;
        const {countText, totalSum, percentageText} = this.state;
        const {size, countY} = this.props;
        let countFontSize = '24';
        let countTextFontSize = '8';
        let cmp;
        if (size) {
            ({countFontSize, countTextFontSize} = SIZES_CONFIG[size]);
        }
        if (countY) {
            countTextY = countY;
        }
        if (percentageText) {
            cmp = (
                <text x={cx} y={countTextY + countTextFontSize} textAnchor="middle">
                    <tspan fontSize={countFontSize} fontWeight="250" fill="#58585B" className="totalcount-text">{`${totalSum}%`}</tspan>
                </text>
            );
        } else {
            cmp = (
                <text x={cx} y={countTextY} textAnchor="middle">
                    <tspan fontSize={countFontSize} fontWeight="250" fill="#58585B" className="totalcount-text">{totalSum}</tspan>
                    <tspan fontSize={countTextFontSize} x={cx} dy={cy / 3} fill="#9E9EA2" className="totalcount-text">{countText}</tspan>
                </text>
            );
        }
        return (
            <g>
                {cmp}
                <Sector
                    cx={cx}
                    cy={cy}
                    innerRadius={innerRadius}
                    outerRadius={outerRadius}
                    startAngle={startAngle}
                    endAngle={endAngle}
                    fill={this.state.fill}
                />
            </g>
        );
    };

    renderLegend() {
        const data = this.props.data || [];
        const colors = this.colors;
        let legend = [];
        data.forEach((item, i) => {
            legend.push(
                <div className="row">
                    <div className="col-1">
                        <div className="legend-marker" style={{backgroundColor: `${colors[i]}`}} />
                    </div>
                    <div className="col-10 chart-text">
                        {item.name + ' (' + item.value + ')'}
                    </div>
                </div>
            );
        });
        return legend;
    }

    renderLegendTooltip() {
        const data = this.props.data || [];
        const colors = this.colors;
        let legend = [];
        data.forEach((item, i) => {
            legend.push(
                <div className="row">
                    <div className="col-4">
                        <div className="legend-marker" style={{backgroundColor: `${colors[i]}`}} />
                    </div>
                    <div className="col-8 chart-text">
                        {item.value}
                    </div>
                </div>
            );
        });
        return legend;
    }

    render() {
        const {customLegendCls, size, countText, hideLegend, className, showLegendTooltip, ...rest} = this.props;
        const data = this.props.data || [];
        const colors = this.colors;
        let {height, width, centerX, centerY, innerRadius, outerRadius} = this.props;
        let legendClasses = ['legend-container'];
        let zeroValueObjs = filter(data, {value: 0});
        let paddingAngle = 4;
        let classes = ['flex', 'flex-left', 'pie-chart'];
        let piechart;

        if (data.length - zeroValueObjs.length === 1) {
            paddingAngle = 0;
        }
        if (size) {
            ({height, width, centerX, centerY, innerRadius, outerRadius} = SIZES_CONFIG[size]);
            classes.push('pie-chart-' + size);
        }
        customLegendCls && legendClasses.push(customLegendCls);
        if (className) {
            classes.push(className);
        }

        piechart = (
            <div className={classes.join(' ')}>
                {data.length === zeroValueObjs.length ? <TotalCount count={0} text={countText} /> :
                    <Chart width={width} height={height} onMouseEnter={this.onPieEnter}>
                        <Pie
                            data={data}
                            activeIndex={this.state.activeIndex}
                            activeShape={this.renderActiveShape}
                            cx={centerX}
                            cy={centerY}
                            innerRadius={innerRadius}
                            outerRadius={outerRadius}
                            fill={this.state.fill}
                            paddingAngle={paddingAngle}
                        >
                            {
                                data.map((entry, index) => <Cell fill={colors[index % colors.length]} stroke={undefined}/>)
                            }
                        </Pie>
                    </Chart>}
                {hideLegend ?
                    null :
                    <div className={legendClasses.join(' ')}>
                        {this.renderLegend(data)}
                    </div>
                }
            </div>
        );

        if (hideLegend && showLegendTooltip) {
            piechart = (<TitledTooltip className="titled-tooltip status-tile-popup" title={''} content={
                <div className="legend-container">{this.renderLegendTooltip(data)}</div>}>
                {piechart}
            </TitledTooltip>);
        }

        return piechart;
    }
}

PieChart.propTypes = {
    data: PropTypes.array.isRequired,
    colors: PropTypes.array,
    className: PropTypes.string,
    hideLegend: PropTypes.bool,
    showLegendTooltip: PropTypes.bool,
    cx: PropTypes.any,
    cy: PropTypes.any,
    innerRadius: PropTypes.any,
    outerRadius: PropTypes.any,
    startAngle: PropTypes.any,
    endAngle: PropTypes.any,
    size: PropTypes.any,
    countY: PropTypes.any,
    customLegendCls: PropTypes.any,
    countText: PropTypes.any,
    height: PropTypes.any,
    width: PropTypes.any,
    centerX: PropTypes.any,
    centerY: PropTypes.any
};

PieChart.defaultProps = {
    data: [
        {
            name: '',
            value: 0

        }
    ],
    colors: []
};

/**
 *
 * @constant PieChart.SIZE
 * @property SMALL {String}
 * @property LARGE {String}
 */
PieChart.SIZE = {
    SMALL: SIZES.SMALL,
    DEFAULT: SIZES.DEFAULT,
    LARGE: SIZES.LARGE,
};

export {PieChart};
