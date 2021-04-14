import React from 'react';
import _ from 'lodash';
import PropTypes from 'prop-types';
import ReactTable from 'react-table';
import 'react-table/react-table.css';
import Chance from 'chance';
import checkboxHOC from 'react-table/lib/hoc/selectTable';

import './Table.scss';

const CheckboxTable = checkboxHOC(ReactTable);
const chance = new Chance();
const CHECKBOX_INPUT_CLASS = 'checkbox__input';

class SimpleCheckboxComponent extends React.Component {
    onClick = (event) => {
        const shiftKey = event.shiftKey;
        event.stopPropagation();
        this.props.onClick(this.props.id, shiftKey, this.props.row);
    };

    render() {
        return (
            <label className="checkbox">
                <input type="checkbox" onClick={this.onClick} checked={this.props.checked} />
                <span className={CHECKBOX_INPUT_CLASS} />
            </label>
        );
    }
}

class SelectTable extends React.Component {
    constructor() {
        super();
        this.state = {
            selection: [],
            selectAll: false
        };
    }

    componentDidMount() {
        if (typeof this.props.getSelected === 'function') {
            this.props.getSelected(this.getSelected);
        }
        if (typeof this.props.clearSelected === 'function') {
            this.props.clearSelected(this.clearSelected);
        }
    }

    componentWillReceiveProps(nextProps) {

    }

    toggleSelection = (key, shift, row) => {
        // start off with the existing state
        let selection = [...this.state.selection];
        const keyIndex = selection.indexOf(key);
        // check to see if the key exists
        if (keyIndex >= 0) {
            // it does exist so we will remove it using destructing
            selection = [
                ...selection.slice(0, keyIndex),
                ...selection.slice(keyIndex + 1)
            ];
        } else {
            // it does not exist so add it
            selection.push(key);
        }
        // update the state
        this.setState({selection});
    };

    toggleAll = () => {
        const selectAll = this.state.selectAll ? false : true;
        const selection = [];
        if (selectAll) {
            // we need to get at the internals of ReactTable
            const wrappedInstance = this.checkboxTable.getWrappedInstance();
            // the 'sortedData' property contains the currently accessible records based on the filter and sort
            const currentRecords = wrappedInstance.getResolvedState().sortedData;
            // we just push all the IDs onto the selection array
            currentRecords.forEach(item => {
                selection.push(item._original._id);
            });
        }
        this.setState({selectAll, selection});
    };

    isSelected = key => {
        return this.state.selection.includes(key);
    };

    clearSelected = () => {
        this.setState({selection: []});
    }

    isActive = (rowInfo) => {
        return this.props.visibleSummaryPane;
    };

    getSelected = () => {
        return this.state.selection;
    };

    getActiveClass = (rowInfo) => {
        // class is decided based on the fact that the Summary pane for this object is currently open or not
        return this.isActive(rowInfo) ? 'active' : '';
    };

    openSummaryPane = (obj) => {
        // row clicked
        const {moClass} = this.props;
        this.props.openSummaryPane({type: moClass, obj: {...obj, ...this.props}});
    };

    openDetailsPane = (obj) => {
        // double clicked
        const {moClass} = this.props;
        this.props.openDetailsScreen(moClass, this.props.data.type, {...obj, ...this.props});
    };

    render() {
        const {toggleSelection, toggleAll, isSelected} = this;
        const {selectAll} = this.state;
        const {data, columns, onRowClick = this.openSummaryPane, onRowDoubleClick = this.openDetailsPane, loading, isLoading, minRows, ...rest} = this.props;

        const checkboxProps = {
            selectAll,
            isSelected,
            toggleSelection,
            toggleAll,
            selectType: 'checkbox'
        };

        return (
            <div>
                <CheckboxTable
                    loading={isLoading}
                    ref={r => (this.checkboxTable = r)}
                    data={data}
                    NoDataComponent={() => isLoading ? null : <div className="rt-noData">No rows found</div>}
                    columns={columns}
                    className="selectable -striped"
                    {...checkboxProps}
                    SelectAllInputComponent={SimpleCheckboxComponent}
                    SelectInputComponent={SimpleCheckboxComponent}
                    getTdProps={(state, rowInfo, column, instance) => {
                        {
                            // console.log('state, rowInfo, column, instance', rowInfo, column);
                            let record, cellValue;
                            const classNames = [];
                            // Get the value returned by backend for the rows that are not empty
                            if (!_.isUndefined(rowInfo)) {
                                record = _.get(rowInfo, 'row', null);
                                cellValue = _.get(record, `${rowInfo.original._id}`, null);
                            }
                            if (typeof cellValue === 'number') {
                                classNames.push('number');
                            }
                            return {
                                className: classNames.join(' '),
                                onClick: (e, handleOriginal) => {
                                    if (typeof rowInfo !== 'undefined' && e.target.className !== CHECKBOX_INPUT_CLASS) { // skip empty rows or row checkbox click
                                        const obj = rowInfo.original;
                                        onRowClick(obj);
                                    }

                                    // 'handleOriginal' function.
                                    if (handleOriginal) {
                                        // handleOriginal();
                                    }
                                },
                                onDoubleClick: (e, handleOriginal) => {
                                    if (typeof rowInfo !== 'undefined' && e.target.className !== CHECKBOX_INPUT_CLASS) { // skip empty rows or row checkbox click
                                        const obj = rowInfo.original;
                                        onRowDoubleClick(obj);
                                    }

                                    // 'handleOriginal' function.
                                    if (handleOriginal) {
                                        // handleOriginal();
                                    }
                                }
                            };
                        }
                    }}
                    getTrProps={(state, rowInfo, column, instance) => {
                        return {
                            className: this.getActiveClass(rowInfo)
                        };
                    }}
                    {...rest}
                />
            </div>
        );
    }
}

SelectTable.propTypes = {
    onClick: PropTypes.func,
    id: PropTypes.string,
    row: PropTypes.any,
    checked: PropTypes.any,
    nextProps: PropTypes.any,
    visibleSummaryPane: PropTypes.func,
    openSummaryPane: PropTypes.func,
    openDetailsScreen: PropTypes.func,
    data: PropTypes.array,
    onRowClick: PropTypes.func,
    onRowDoubleClick: PropTypes.func,
    loading: PropTypes.func,
    isLoading: PropTypes.bool,
    getSelected: PropTypes.func,
    clearSelected: PropTypes.func,
    moClass: PropTypes.string,
    minRows: PropTypes.number,
    columns: PropTypes.array,
};

SelectTable.defaultProps = {
    defaultPageSize: 10
};

export {SelectTable};
