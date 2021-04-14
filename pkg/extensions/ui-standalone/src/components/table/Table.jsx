import React from 'react';
import PropTypes from 'prop-types';
import _ from 'lodash';
import ReactTable from 'react-table';

import './Table.scss';

const EMPTY_CELL_PLACEHOLDER = '-';
const FILTER_HOVER_CLASS = 'icon-filter icon-small hover-filter-icon';
const NUMBER = 'number';

class Table extends React.Component {
    constructor() {
        super();
    }

    openSummaryPane = (obj) => {
        // row clicked
        const {moClass} = this.props;
        this.props.openSummaryPane({type: moClass, obj: obj});
    };

    openDetailsPane = (obj) => {
        // double clicked
        const {moClass} = this.props;
        this.props.openDetailsScreen(moClass, this.props.data.type, obj);
    };

    isActive = (rowInfo) => {
        // return this.props.visibleSummaryPane && this.props.visibleSummaryPane.dn === _.get(rowInfo, 'original.dn');
    };

    getActiveClass = (rowInfo) => {
        // class is decided based on the fact that the Summary pane for this object is currently open or not
        // return this.isActive(rowInfo) ? 'active' : '';
    };

    render() {
        const {onRowClick = this.openSummaryPane, onRowDoubleClick = this.openDetailsPane, columns, data, loading, ...rest} = this.props;

        return (
            <ReactTable
                className="-striped"
                loading={loading}
                data={data}
                NoDataComponent={() => loading ? null : <div className="rt-noData">No rows found</div>}
                columns={columns}
                getTdProps={(state, rowInfo, column, instance) => {
                    let record, cellValue;
                    const classNames = [];
                    // Get the value returned by backend for the rows that are not empty
                    if (!_.isUndefined(rowInfo)) {
                        record = _.get(rowInfo, 'row', null);
                        cellValue = _.get(record, `${column.id}`, null);
                    }
                    const filterType = _.get(column, 'filter.type');
                    if (typeof cellValue === NUMBER || filterType === NUMBER) {
                        classNames.push(NUMBER);
                    }
                    return {
                        className: classNames.join(' '),
                        onClick: (e, handleOriginal) => {
                            if (typeof rowInfo !== 'undefined' && e.target.className !== FILTER_HOVER_CLASS) { // skip empty rows
                                const obj = rowInfo.original;
                                onRowClick(obj);
                            }

                            // 'handleOriginal' function.
                            if (handleOriginal) {
                                handleOriginal();
                            }
                        },
                        /*
                         having both click and double click on the same element is actually tricky,
                         because the single click event will still be dispatched (twice)
                         Possible mitigations are to have a timer on the click that will wait and check for the double or similar
                         In our implementation is not too big of an issue (opens the summary) so we can ignore it, just keeping it in mind
                         */
                        onDoubleClick: (e, handleOriginal) => {
                            if (typeof rowInfo !== 'undefined' && e.target.className !== FILTER_HOVER_CLASS) { // skip empty rows
                                const obj = rowInfo.original;
                                onRowDoubleClick(obj);
                            }

                            // 'handleOriginal' function.
                            if (handleOriginal) {
                                handleOriginal();
                            }
                        }
                    };
                }}
                getTrProps={(state, rowInfo, column, instance) => {
                    return {
                        className: this.getActiveClass(rowInfo)
                    };
                }}
                {...rest}
            />
        );
    }
}

Table.propTypes = {
    defaultPageSize: PropTypes.number,
    onRowClick: PropTypes.func,
    columns: PropTypes.array,
    data: PropTypes.array,
    loading: PropTypes.bool,
    moClass: PropTypes.string,
    openDetailsScreen: PropTypes.func,
    openSummaryPane: PropTypes.func,
    onRowDoubleClick: PropTypes.func,
};

Table.defaultProps = {
    defaultPageSize: 10
};

export {Table};
