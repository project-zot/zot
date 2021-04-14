import React from 'react';
import PropTypes from 'prop-types';
import {isEmpty, isEqual} from 'lodash';
import {Icon, Input, Select, HelpBlock} from 'blueprint-react';

import {PlainTable} from './PlainTable';

import {removeLeadTrailSpaces} from '../../common/utils/validation-utils';

import './EditableTable.scss';

const NON_EDITING_STATE = {
    editingIndex: -1,
    editingObject: null,
    editingObjectValidity: null,
    showValidationError: false
};

const EDITOR_TYPE = {
    ...Input.TYPE,
    SELECT: 'select',
};

class EditableTable extends React.Component {
    constructor(props) {
        super(props);

        this.state = {
            ...NON_EDITING_STATE,
            ...this.convertPropToState(props)
        };
    }

    componentDidUpdate(prevProps) {
        if (!isEqual(prevProps.data, this.props.data) && !isEqual(this.props.data, this.state.tableData)
            || !isEqual(prevProps.columns, this.props.columns)
        ) {
            this.tableDataUpdated();
        }
    }

    tableDataUpdated = () => {
        this.setState({
            ...NON_EDITING_STATE,
            ...this.convertPropToState(this.props)
        });
    }

    onSelectChange = (selectedObj, column) => {
        const {editingObject, editingObjectValidity} = this.state;
        const {accessor} = column;

        if (isEmpty(selectedObj[0])) {
            return;
        }
        const value = selectedObj[0].name;
        const prevValidity = editingObjectValidity && accessor && editingObjectValidity[accessor];
        let objValidity = {...editingObjectValidity};
        let newState = {
            editingObject: {
                ...editingObject,
                [accessor]: value
            }
        };

        // clear the old error because field is required while value was empty
        if (typeof prevValidity !== 'undefined' && prevValidity !== true) {
            delete objValidity[accessor];
            newState.editingObjectValidity = objValidity;
        }

        this.setState(newState);
    }

    onInputChange = (event, column) => {
        const {noLeadTrailSpaces} = this.props;
        const {editingObject, editingObjectValidity} = this.state;
        let value = event.target.value;
        const {accessor, editor} = column;
        let validateResult;

        if (noLeadTrailSpaces) {
            value = removeLeadTrailSpaces(value);
        }
        let newState = {
            editingObject: {
                ...editingObject,
                [accessor]: value
            }
        };
        if (typeof editor.validator === 'function') {
            // validate result can be true, false, or error message
            validateResult = editor.validator(value, editingObject);

            newState.editingObjectValidity = {
                ...editingObjectValidity,
                [accessor]: validateResult
            };
        }
        this.setState(newState);
    }

    editableCell = (column, rowData, rowIdx) => {
        const {accessor, editor, origCell} = column;
        const {editingIndex, editingObject, editingObjectValidity, showValidationError} = this.state;
        let cmpValid = true;
        let editorCmp, cmpHelp;

        if (editingIndex === rowIdx) {
            if (editor) {
                const editingValue = editingObject[accessor];
                const validity = editingObjectValidity[accessor];
                const isValidValue = typeof validity === 'undefined' || validity === true;

                // validation errors would not be show until user tries to save the row for the first time
                if (showValidationError && !isValidValue) {
                    cmpValid = false;
                    cmpHelp = {
                        message: validity || 'Invalid value',
                        type: HelpBlock.TYPE.ERROR
                    };
                }

                switch (editor.type) {
                    case EDITOR_TYPE.SELECT:
                        const selectItems = editor.selectItems ? editor.selectItems.map((item, idx) => {
                            return {
                                name: item,
                                label: item,
                                value: idx,
                                selected: editingValue === item
                            };
                        }) : [];
                        editorCmp = (
                            <Select
                                items={selectItems}
                                size={Select.SIZE.COMPRESSED}
                                help={cmpHelp}
                                onChange={(selectedObj) => {
                                    this.onSelectChange(selectedObj, column);
                                }} />
                        );
                        break;
                    case EDITOR_TYPE.NUMBER:
                    case EDITOR_TYPE.TEXT:
                    case EDITOR_TYPE.URL:
                    default:
                        editorCmp = (
                            <Input
                                value={editingValue}
                                type={editor.type}
                                size={Input.SIZE.COMPRESSED}
                                // required={editor.isRequired}
                                valid={cmpValid}
                                // error={!isValidValue}
                                help={cmpHelp}
                                onChange={(event) => {
                                    this.onInputChange(event, column);
                                }} />
                        );
                }
                return <div>{editorCmp}</div>;
            }
        } else if (typeof origCell === 'function') {
            return origCell(rowData, rowIdx);
        }
        return (<div>{rowData.original[accessor]}</div>);
    }

   locationIconCell = (rowData, rowIdx) => {
       const {editingIndex} = this.state;
       let iconClass = '';
       if (rowData.original.geoLocation.lat && rowData.original.geoLocation.long) {
           iconClass = 'icon-selected';
       }
       // only when editing
       if (editingIndex === rowIdx) {
           return (
               <div
                   className="row-action"
                   onClick={() => {
                       this.onSaveEditRow();
                   }}
               >
                   <Icon type={Icon.TYPE.LOCATION} size={Icon.SIZE.SMALL}/>
               </div>);
       }
       return (
           <div
               className="row-action"
               onClick={() => {
                   this.onLocationRowClick(rowData.original, rowIdx);
               }}
           >
               <Icon className={iconClass} type={Icon.TYPE.LOCATION} size={Icon.SIZE.SMALL}/>
           </div>);
   }

    editIconCell = (rowData, rowIdx) => {
        const {editingIndex} = this.state;
        if (rowData.original.notEditable) {
            return <div />;
        }
        if (editingIndex === rowIdx) {
            return (
                <div
                    className="row-action"
                    onClick={() => {
                        this.onSaveEditRow();
                    }}
                >
                    <Icon type={Icon.TYPE.CHECK} size={Icon.SIZE.SMALL} />
                </div>);
        }
        return (
            <div
                className="row-action"
                onClick={() => {
                    this.onEditRowClick(rowData.original, rowIdx);
                }}
            >
                <Icon type={Icon.TYPE.EDIT} size={Icon.SIZE.SMALL} />
            </div>);
    }

    deleteIconCell = (rowData, rowIdx) => {
        const {editingIndex} = this.state;
        if (rowData.original.notDeletable) {
            return <div />;
        }
        if (editingIndex === rowIdx) {
            return (
                <div
                    className="row-action"
                    onClick={() => {
                        this.onCancelEditRow();
                    }}
                >
                    <Icon type={Icon.TYPE.CLOSE} size={Icon.SIZE.SMALL} />
                </div>);
        }
        return (
            <div
                className="row-action"
                onClick={() => {
                    this.onDeleteRowClick(rowData.original, rowIdx);
                }}
            >
                <Icon type={Icon.TYPE.TRASH} size={Icon.SIZE.SMALL} />
            </div>);
    }

    convertPropToState(props) {
        let {data, columns, onLocationRowClick, isEditable = true, isDeletable = true} = props;
        let newData = data && [...data] || [];
        let newColumns = [...columns];

        // attach cell renderer to text input box for edit mode
        newColumns = newColumns.map((column) => {
            let newColumn = {
                ...column,
                origCell: column.Cell
            };
            return {
                ...newColumn,
                Cell: (rowData, rowIdx) => {
                    return this.editableCell(newColumn, rowData, rowIdx);
                },
            };
        });

        if (typeof onLocationRowClick === 'function') {
            newColumns.push({
                Header: '',
                accessor: 'locationRow',
                className: 'icon-cell',
                Cell: this.locationIconCell
            });
        }

        if (isEditable) {
            newColumns.push({
                Header: '',
                accessor: 'editRow',
                className: 'icon-cell',
                Cell: this.editIconCell
            });
        }

        if (isDeletable)  {
            newColumns.push({
                Header: '',
                accessor: 'deleteRow',
                className: 'icon-cell',
                Cell: this.deleteIconCell
            });
        }

        return {
            tableData: newData,
            tableColumns: newColumns
        };
    }

    // notify parent component that the table data have been changed
    // it is recommended to used only one of the followings:
    //   - onXxxHandler: the parent component handles all the data changes and pass the data to the Editable component as props
    //   - onChange: the EditableTable component handles all the data changes with in-line editor and parent component will get notified
    onChange = (tableData) => {
        const {onChange} = this.props;

        if (typeof onChange === 'function') {
            onChange(tableData);
        }
    }

    // is used to notify parent component that edit mode is on/off,
    // and parent compnent needs to enable/disable form submit button accordingly
    onEditModeToggle = () => {
        const {onEditModeToggle} = this.props;
        const {editingIndex} = this.state;

        if (typeof onEditModeToggle === 'function') {
            onEditModeToggle(editingIndex !== NON_EDITING_STATE.editingIndex);
        }
    }

    onCancelEditRow = () => {
        this.setState({
            ...NON_EDITING_STATE
        }, this.onEditModeToggle);
    }

    getRowValidity = (rowObj) => {
        const {columns} = this.props;
        const {editingObjectValidity} = this.state;
        let validity = {};
        let isValid = true;

        if (isEmpty(columns)) {
            return validity;
        }
        columns.forEach((column) => {
            const {accessor, editor} = column;
            const validator = editor && editor.validator;
            const isRequired = editor && editor.isRequired;
            const value = accessor && rowObj[accessor];

            if (isRequired && isEmpty(value)) {
                validity[accessor] = 'Required';
                isValid = false;
            } else if (typeof validator === 'function') {
                validity[accessor] = validator(value, rowObj);
                if (validity[accessor] !== true) {
                    isValid = false;
                }
            }
        });

        if (!isValid) {
            this.setState({
                editingObjectValidity: {...validity},
                showValidationError: true
            });
        }

        return isValid;
    }

    onSaveEditRow = () => {
        const {tableData, editingObject, editingIndex} = this.state;
        let newTableData = [...tableData];

        if (!this.getRowValidity(editingObject)) {
            return;
        }

        if (newTableData.length <= editingIndex) {
            newTableData.push(editingObject);
        } else if (editingIndex >= 0) {
            newTableData.splice(editingIndex, 1, editingObject);
        }

        this.setState({
            ...NON_EDITING_STATE,
            tableData: newTableData
        }, () => {
            this.onChange(newTableData);
            this.onEditModeToggle();
        });
    }

    onAddRowClick = () => {
        const {addRowHandler} = this.props;
        const {tableData} = this.state;

        if (typeof addRowHandler === 'function') {
            addRowHandler();
        } else {
            this.setState({
                editingIndex: tableData.length,
                editingObject: {},
                editingObjectValidity: {},
                showValidationError: false
            }, this.onEditModeToggle);
        }
    }

    onLocationRowClick = (rowData, rowIdx) => {
        const {onLocationRowClick} = this.props;
        if (typeof onLocationRowClick === 'function') {
            onLocationRowClick(rowData);
        }
    }

    onEditRowClick = (rowData, rowIdx) => {
        const {editRowHandler} = this.props;

        if (typeof editRowHandler === 'function') {
            editRowHandler(rowData, rowIdx);
        } else {
            this.setState({
                editingIndex: rowIdx,
                editingObject: {...rowData},
                editingObjectValidity: {},
                showValidationError: false
            }, this.onEditModeToggle);
        }
    }

    onDeleteRowClick = (rowData, rowIdx) => {
        const {deleteRowHandler} = this.props;
        const {tableData} = this.state;
        let newTableData;

        if (typeof deleteRowHandler === 'function') {
            deleteRowHandler(rowData, rowIdx);
        } else {
            newTableData = tableData && [...tableData] || [];
            newTableData.splice(rowIdx, 1); // delete the row data
            this.setState({
                tableData: newTableData,
            });
            this.onChange(newTableData);
        }
    }

    renderTable = () => {
        const {tableData, tableColumns, editingIndex, editingObject} = this.state;
        let adjustedTableData = [...tableData];

        // adding a row
        if (editingIndex >= tableData.length) {
            adjustedTableData.push(editingObject);
        }

        return <PlainTable data={adjustedTableData} columns={tableColumns} />;
    }

    renderAddRowAction = () => {
        const {addRowLabel, maxRows} = this.props;
        const {editingIndex, tableData} = this.state;

        // adding a row
        if (editingIndex >= tableData.length) {
            return;
        }

        if (maxRows && maxRows <= tableData.length) {
            return;
        }
        if (addRowLabel) {
            return (
                <a className="add-row-action" onClick={this.onAddRowClick}>
                    <Icon type={Icon.TYPE.ADD_CONTAIN} />
                    {addRowLabel}
                </a>
            );
        }
    }

    render() {
        return (
            <div className="EditableTable">
                {this.renderTable()}
                {this.renderAddRowAction()}
            </div>
        );
    }
}

EditableTable.EDITOR_TYPE = EDITOR_TYPE;

EditableTable.propTypes = {
    data: PlainTable.propTypes.data,
    columns: PlainTable.propTypes.columns.isRequired,

    addRowLabel: PropTypes.string,
    maxRows: PropTypes.number,

    // action handlers
    addRowHandler: PropTypes.func,
    deleteRowHandler: PropTypes.func,
    editRowHandler: PropTypes.func,

    // data change notification
    onChange: PropTypes.func,
    // onEditModeToggle (isEditing: bool)
    onEditModeToggle: PropTypes.func,

    noLeadTrailSpaces: PropTypes.bool
};

EditableTable.defaultProps = {
    noLeadTrailSpaces: true
};

export {EditableTable};
