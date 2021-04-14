import React from 'react';
import PropTypes from 'prop-types';
import _ from 'lodash';
import {StructuredFilter} from 'blueprint-react';

import {Table} from './Table';
import {SelectTable} from './SelectTable';
import FilterableCell from './FilterableCell';
import LABELS from '../../strings';

import './FilterableTable.scss';

const FILTER_FUNCTIONS = {
    '==': (o, colData, filterInfo) => {
        if (typeof colData.accessor === 'function') {
            return String(colData.accessor(o)).toLowerCase() === String(filterInfo.value).toLowerCase();
        }
        return (_.get(o, colData.accessor, '') || '').toString().toLowerCase() === String(filterInfo.value).toLowerCase();
    },
    '!=': (o, colData, filterInfo) => {
        if (typeof colData.accessor === 'function') {
            return String(colData.accessor(o)).toLowerCase() !== String(filterInfo.value).toLowerCase();
        }
        return (_.get(o, colData.accessor, '') || '').toString().toLowerCase() !== String(filterInfo.value).toLowerCase();
    },
    '>': (o, colData, filterInfo) => {
        if (typeof colData.accessor === 'function') {
            return Number(colData.accessor(o)) > Number(filterInfo.value);
        }
        return _.get(o, colData.accessor, NaN) > Number(filterInfo.value);
    },
    '>=': (o, colData, filterInfo) => {
        if (typeof colData.accessor === 'function') {
            return Number(colData.accessor(o)) >= Number(filterInfo.value);
        }
        return _.get(o, colData.accessor, NaN) >= Number(filterInfo.value);
    },
    '<': (o, colData, filterInfo) => {
        if (typeof colData.accessor === 'function') {
            return Number(colData.accessor(o)) < Number(filterInfo.value);
        }
        return _.get(o, colData.accessor, NaN) < Number(filterInfo.value);
    },
    '<=': (o, colData, filterInfo) => {
        if (typeof colData.accessor === 'function') {
            return Number(colData.accessor(o)) <= Number(filterInfo.value);
        }
        return _.get(o, colData.accessor, NaN) <= Number(filterInfo.value);
    },
    contains: (o, colData, filterInfo) => {
        if (typeof colData.accessor === 'function') {
            return _.includes(String(colData.accessor(o)).toLowerCase(), String(filterInfo.value).toLowerCase());
        }
        return _.includes(String(_.get(o, colData.accessor, '')).toString().toLowerCase(), String(filterInfo.value).toLowerCase());
    },
    '!contains': (o, colData, filterInfo) => {
        if (typeof colData.accessor === 'function') {
            return !_.includes(String(colData.accessor(o)).toLowerCase(), String(filterInfo.value).toLowerCase());
        }
        return !_.includes(String(_.get(o, colData.accessor, '')).toString().toLowerCase(), String(filterInfo.value).toLowerCase());
    }
};

export default class FilterableTable extends React.Component {
    constructor(props) {
        super(props);

        this.state = {
            filterExp: []
        };

        this.filterFields = [];
        this.columnsData = {};
        props.columns.forEach((col) => {
            const category = col.id || col.accessor;
            this.columnsData[category] = col;
            if (col.filterable !== false) { // default is filterable
                this.filterFields.push({
                    category: category,
                    categoryLabel: col.filterLabel || col.Header,
                    type: col.filterType || 'text'
                });
            }
        });

        /* this.filterFields.push({
            category: 'anyText',
            categoryLabel: LABELS.anyText,
            type: 'text'
        });*/
    }

    componentDidMount() {
        this.updateTable(this.props.data);
    }

    componentDidUpdate(prevProps) {
        const {data} = this.props;

        if (typeof data !== 'undefined' && data !== prevProps.data) {
            this.updateTable(data);
        }
    }

    _invokeApplyFilter = (filterExp) => {
        this.setState({loading: true});
        this.props.applyFilter(filterExp).then((filteredData) => {
            this.filteredData = filteredData;
            this.setState({loading: false});
        }, (e) => {
            this.setState({loading: false});
        });
    };

    updateTable = (data) => {
        this.data = data;
        if (!this.props.applyFilter) {
            this.filterCurrentData();
        } else {
            this._invokeApplyFilter(this.state.filterExp);
        }
    };

    onFilterChange = (filterExp) => {
        if (!this.props.applyFilter) {
            // filter the data we have
            this.setState({filterExp: filterExp || []}, this.filterCurrentData);
        } else {
            // let client code take care of determining filtered data (e.g. by calling an api,
            // then updating "data" attribute with results (transformed to fit expected model)
            this._invokeApplyFilter(filterExp);
        }
    };

    filterCurrentData() {
        this.filteredData = this.data || [];
        this.state.filterExp.forEach((subExp) => {
            const colData = this.columnsData[subExp.category];
            /* if (subExp.category === 'anyText') {
                this.filteredData = _.filter(this.filteredData, (o) => {
                    const ret = _.includes(_.get(o, colData.accessor, '').toLowerCase(), subExp.value.toLowerCase());

                    if (subExp.operator === '!=' || subExp.operator === '!contains') {
                        return !ret;
                    }
                    return ret;
                });
            } else {*/
            this.filteredData = _.filter(this.filteredData, (o) => {
                if (typeof colData.filterFunc === 'function') {
                    return colData.filterFunc(o, subExp);
                }
                return FILTER_FUNCTIONS[subExp.operator](o, colData, subExp);
            });
            // }
        });
        this.setState({loading: false});
    }

    render() {
        const {isLoading, selectable, tools, data, ...rest} = this.props;
        let table;

        if (selectable) {
            table = (
                <SelectTable
                    getSelected={(f) => {
                        this.getSelected = f;
                    }}
                    isLoading={this.state.loading || isLoading}
                    data={this.filteredData}
                    {...rest}
                />
            );
        } else {
            table = (
                <Table
                    loading={this.state.loading || isLoading}
                    data={this.filteredData}
                    {...rest}
                />
            );
        }

        let headerTools;
        if (tools && tools.length) {
            headerTools = <span className="header--tools" >{tools}</span>;
        }

        return (
            <div className="filterable-table">
                <header>
                    <StructuredFilter placeholder={LABELS.searchPlaceHolder}
                        onChange={this.onFilterChange}
                        options={this.filterFields}
                    />
                    {headerTools}
                </header>
                <div>
                    {table}
                </div>
            </div>
        );
    }
}

FilterableTable.propTypes = {
    columns: PropTypes.array.isRequired,
    // the raw data that may be filtered
    data: PropTypes.array,
    selectable: PropTypes.bool,
    /**
     * if not set, filter on current data as opposed to externally, most likely by invoking an api call that would respond with the a response
     * that can be transformed to the schema defined by props.columns.  The transformed data should be bound to the data attribute.
     * function that takes a filter expression and returns a resolved promise with the filtered data
     */
    applyFilter: PropTypes.func,
    isLoading: PropTypes.bool,
    /**
     * List of "tools" e.g. any react components like icon buttons, select component, checkboxes, or string, number etc.
     * The tools are located on the upper right portion of the Card.
     */
    tools: PropTypes.arrayOf(PropTypes.node)
};

FilterableTable.defaultProps = {
    filteredData: [],
    selectable: false,
    isLoading: false,
    // PaginationComponent: PaginationBar
};
