import React from 'react';
import PropTypes from 'prop-types';
import {Loader} from 'blueprint-react';
import * as d3 from 'd3';

import './LineGraph.scss';

class LineGraph extends React.Component {
    constructor(props) {
        super(props);
    }

    componentDidMount() {
        this.update();
    }

    componentDidUpdate(prevProps) {
        if (prevProps.pageReload !== this.props.pageReload) {
            this.update();
        }
    }

    update = () => {
        /*
        * Retrieves data from React parent component.
        */
        const {data, id, yAxisLabel, xWidth} = this.props;
        const HEIGHT = 60;
        /*
        * Checks if our react chart component (id) is already rendered.
        * If not (first time the component is intanciated : before componentDidMount) : it exits from the update function.
        * If ok (component already instanciated : during or after componentDidMount) : it runs the update function.
        */
        const chartComponentSelection = d3.select(`#chart-${id}`);

        if (chartComponentSelection.empty()) {
            return;
        }

        /*
        * Clean previous graphic each time an update is needed by removing the svg element.
        * It avoids that graphics are added/displayed one after the other.
        */
        const mainSvgSelection = d3.select(`#${id}`);
        if (!mainSvgSelection.empty()) {
            mainSvgSelection.remove();
        }

        // Scales are defined to let some space for displaying axis
        const xScale = d3
            .scaleTime()
            .domain(
                d3.extent(data, function(d) {
                    return d.x;
                })
            )
            .range([0, xWidth]);

        const yScale = d3
            .scaleLinear()
            .domain(
                d3.extent(data, function(d) {
                    return +d.y;
                })
            )
            .range([HEIGHT, 0]);

        // We define the line function which will build the graphic for each data "d" of new data.
        const line = d3
            .line()
            .x(function(d) {
                return xScale(d.x);
            })
            .y(function(d) {
                return yScale(d.y);
            })
            .curve(d3.curveMonotoneX);

        // svg component width , height
        const svg = chartComponentSelection
            .append('svg')
            .attr('id', id)
            .attr('preserveAspectRatio', 'xMinYMin meet')
            .attr('width', '100%')
            .attr('height', '100%')
            .classed('svg-content', true)
            .append('g')
            .attr('transform', 'translate(40,55)');

        // xAxis
        svg
            .append('g')
            .attr('transform', 'translate(0, 60)')
            .call(d3.axisBottom(xScale)
                .ticks(0)
                .tickSizeOuter(0)
            )
            .style('stroke-dasharray', '10 5')
            .append('text')
            .attr('class', 'chartXAxisLabel')
            .attr('x', xWidth / 2)
            .attr('dy', '1.5em')
            .attr('text-anchor', 'end')
            .style('fill', 'black')
            .style('font-size', '12px')
            .text('Time');

        // yAxis
        svg
            .append('g')
            .attr('transform', 'translate(0,0)')
            .call(d3.axisLeft(yScale)
                .ticks(0)
                .tickSizeOuter(0)
            )
            .style('stroke-dasharray', '10 5')
            .append('text')
            .attr('class', 'chartYAxisLabel')
            .attr('transform', 'rotate(-90)')
            .attr('y', 0)
            .attr('dy', '-1.5em')
            .attr('text-anchor', 'end')
            .style('fill', 'black')
            .style('font-size', '12px')
            .text(yAxisLabel);

        // Adds line graph
        svg
            .append('path')
            .datum(data)
            .attr('fill', 'none')
            .attr('stroke', 'steelblue')
            .attr('stroke-linejoin', 'round')
            .attr('stroke-linecap', 'round')
            .attr('stroke-width', 1.5)
            .attr('d', line);

        // Defines an area for gradiacion display
        const area = d3
            .area()
            .x(function(d) {
                return xScale(d.x);
            })
            .y0(HEIGHT)
            .y1(function(d) {
                return yScale(d.y);
            });

        // Defines gradient
        svg
            .append('linearGradient')
            .attr('id', 'areachart-gradient')
            .attr('gradientUnits', 'userSpaceOnUse')
            .attr('x1', '0%')
            .attr('x2', '0%')
            .attr('y1', '0%')
            .attr('y2', '100%')
            .selectAll('stop')
            .data([
                {offset: '0%', color: '#F7FBFE'},
                {offset: '100%', color: '#3498DB'}
            ])
            .enter()
            .append('stop')
            .attr('offset', function(d) {
                return d.offset;
            })
            .attr('stop-color', function(d) {
                return d.color;
            });

        // Displays gradient
        svg
            .append('path')
            .datum(data)
            .style('fill', 'url(#areachart-gradient)')
            .style('opacity', '0.6')
            .attr('d', area);

        const bisectDate = d3.bisector(function(d) {
            return d.x;
        }).left;

        function addTooltip() {
            // Group that contains the whole tooltip and the moving circle on the line
            const tooltip = svg
                .append('g')
                .attr('id', `tooltip-${id}`)
                .style('display', 'none');

            // External light blue circle of the moving circle
            tooltip
                .append('circle')
                .attr('fill', '#CCE5F6')
                .attr('r', 10);

            // Inner blue circle of the moving circle
            tooltip
                .append('circle')
                .attr('fill', '#3498db')
                .attr('stroke', '#fff')
                .attr('stroke-width', '1.5px')
                .attr('r', 4);

            tooltip
                .append('polyline')
                .attr('points', '0,0 0,20 25,20 30,25 35,20 60,20 60,0 0,0')
                .style('fill', '#fafafa')
                .style('stroke', '#3498db')
                .style('opacity', '0.9')
                .style('stroke-width', '2')
                .attr('transform', 'translate(-30, -35)');

            const text = tooltip
                .append('text')
                .style('font-size', '16px')
                .style('font-family', 'Segoe UI')
                .style('color', 'black')
                .style('fill', 'black')
                .attr('transform', 'translate(-20, -20)');

            text
                .append('tspan')
                .attr('dx', '0')
                .attr('dy', '0')
                .attr('id', `tooltip-y-${id}`);

            return tooltip;
        }

        const tooltip = addTooltip();

        function mousemove() {
            let d = null;
            const x0 = xScale.invert(d3.mouse(this)[0]);
            const i = bisectDate(data, x0);
            d = data[i];
            if (i === data.length) {
                d = data[i - 1];
            }

            tooltip.attr(
                'transform',
                'translate(' + xScale(d.x) + ',' + yScale(d.y) + ')'
            );

            let text = d.y;
            d3.select(`#tooltip-y-${id}`).text(text);
        }

        svg
            .append('rect')
            .attr('class', 'overlay')
            .attr('width', '100%')
            .attr('height', HEIGHT)

            .on('mouseover', function() {
                tooltip.style('display', null);
            })
            .on('mouseout', function() {
                tooltip.style('display', 'none');
            })
            .on('mousemove', mousemove);
    };

    render() {
        const {isLoading, id} = this.props;

        if (isLoading !== undefined && isLoading) {
            return <Loader />;
        }

        return (
            <div id={`chart-${id}`} className="svg-container" />
        );
    }
}

LineGraph.propTypes = {
    pageReload: PropTypes.number,
    data: PropTypes.array,
    id: PropTypes.string,
    yAxisLabel: PropTypes.string,
    xWidth: PropTypes.number,
    isLoading: PropTypes.bool
};

export {LineGraph};
