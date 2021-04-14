import React from 'react';
import PropTypes from 'prop-types';
import _ from 'lodash';
import Chance from 'chance';
import {isEqual, isEmpty} from 'lodash';
import {FilterableTable} from 'blueprint-react';
import LABELS from '../../strings';

import './SeFilterableTable.scss';

const chance = new Chance();
const CHECKBOX_INPUT_CLASS = 'checkbox__input';

class SeFilterableTable extends React.Component {
    constructor(props) {
        super(props);
        this.state = {
            data: [],
        };
        this.processedData = [];
    }

    componentDidMount() {
        this.tableDataUpdated();
    }

    componentDidUpdate(prevProps) {
        if (!isEqual(prevProps.data, this.props.data)) {
            this.tableDataUpdated();
        }
    }

    tableDataUpdated() {
        const {data, columns, selectable, primaryKey} = this.props;
        let processedData = isEmpty(data) ? [] : [...data];
        // sort by the first column by default
        const sortByAccessor = primaryKey || (isEmpty(columns) ? '' : columns[0].accessor);

        if (sortByAccessor) {
            processedData.sort((data1, data2) => (data1[sortByAccessor] > data2[sortByAccessor] ? 1 : -1));
            if (!isEqual(processedData, this.processedData)) {
                this.processedData = processedData;
                if (selectable) {
                    this.setState({
                        data: processedData.map((item) => {
                            return {
                                ...item,
                                _id: chance.guid(), // default keyField accessor for select table to identify row with unique id
                            };
                        }),
                    });
                } else {
                    this.setState({data: processedData});
                }
            }
        }
    }

    render() {
        const {moClass, selectable, ...rest} = this.props;
        const {data} = this.state;
        let tableProps = {
            ...rest,
            data,
            selectable,
            getTdProps: this.getTdProps,
            addFilterPills: (f) => {
                this.addFilterPills = f;
            },
            getSelected: (f) => {
                if (typeof f === 'function') {
                    this.getSelected = f;
                    this.props.getSelected(f);
                }
            },
        };

        return <FilterableTable {...tableProps} />;
    }

    getTdProps = (state, rowInfo, column, instance) => {
        const {onTdRowClick, onTdDoubleClick} = this.props;
        // eslint-disable-line
        return {
            onClick: (e, handleOriginal) => {
                if (typeof rowInfo !== 'undefined' && e.target.className !== CHECKBOX_INPUT_CLASS) {
                    // skip empty rows or row checkbox click
                    const rowData = rowInfo.original;
                    if (onTdRowClick) {
                        onTdRowClick(e, state, rowInfo, column, instance);
                    } else {
                        const summaryPaneExists = !_.isUndefined(this.props.openSummaryPane);
                        if (summaryPaneExists) {
                            // this.props.openSummaryPane({type: this.props.moClass, obj: {...rowData, successCallBack: this.props.successCallBack}});
                        }
                    }
                }
            },
            onDoubleClick: (e) => {
                if (typeof rowInfo !== 'undefined' && e.target.className !== CHECKBOX_INPUT_CLASS) {
                    // skip empty rows or row checkbox click
                    const rowData = rowInfo.original;
                    if (onTdDoubleClick) {
                        onTdDoubleClick(event, state, rowInfo, column, instance);
                    } else {
                        const openDetailsExists = !_.isUndefined(this.props.openDetailsScreen);
                        if (openDetailsExists) {
                            this.props.openDetailsScreen(this.props.moClass, rowData.name, {...rowData, successCallBack: this.props.successCallBack});
                        }
                    }
                }
            },
        };
    };
}

SeFilterableTable.propTypes = {
    ...FilterableTable.propTypes,
    moClass: PropTypes.string,
};

export {SeFilterableTable};
