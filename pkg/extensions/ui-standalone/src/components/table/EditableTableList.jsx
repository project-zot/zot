import React from 'react';
import PropTypes from 'prop-types';
import _ from 'lodash';
import {Input} from 'blueprint-react';

import {isIpValid, isValidHostName} from '../../common/utils/validation-utils';
import LABELS from '../../strings';

import './EditableTableList.scss';

const NBSP = '\u00A0';
const FIELD_TYPE = {
    IP: 'ip',
    DOMAIN_NAME: 'domainName'
};

class EditableTableList extends React.Component {
    constructor(props) {
        super(props);
        this.state = {
            newRow: false,
            newRowValue: '',
            editIndex: -1,
            fields: !_.isEmpty(props.fieldData) && [...props.fieldData] || [],
            fieldError: {status: false, message: ''}
        };
    }

    addRow = () => {
        this.setState({newRow: true, newRowValue: ''}, this.validateList);
    }

    saveRow = (index) => {
        const {fields} = this.state;
        if (index >= 0) {
            if (this.validateField(fields[index])) {
                this.setState({editIndex: -1}, this.onFieldsUpdated);
            }
        } else {
            const {newRowValue} = this.state;
            if (!_.isEmpty(newRowValue) && this.validateField(newRowValue)) {
                this.setState((prevState) => ({
                    fields: [...prevState.fields, newRowValue], newRow: false, newRowValue: '   '
                }), this.onFieldsUpdated);
            }
        }
    }

    cancelRow = (index) => {
        const {fields} = this.state;
        if (index >= 0) {
            if (this.validateField(fields[index])) {
                this.setState({editIndex: -1}, this.validateList);
            }
        } else {
            this.setState({newRow: false, newRowValue: '', fieldError: {message: '', status: false}}, this.validateList);
        }
    }

    editRow = (index) => {
        this.setState({editIndex: index}, this.validateList);
    }

    deleteRow = (index) => {
        let {fields} = this.state;
        fields.splice(index, 1);
        this.setState({fields}, this.onFieldsUpdated);
    }

    handleChange = (e, index) => {
        const {fields} = this.state;
        const value = e.target.value;
        if (index >= 0) {
            fields[index] = value;
            this.setState({fields});
        } else {
            this.setState({newRowValue: value});
        }
    }

    onFieldsUpdated = () => {
        const {id, getSetUpValue} = this.props;
        const {fields} = this.state;

        if (getSetUpValue && typeof getSetUpValue === 'function') {
            getSetUpValue(fields, id);
        }
        this.validateList();
    }

    validateList = () => {
        const {setValidity, minEntries} = this.props;
        const {editIndex, newRow, fields} = this.state;
        let isValid = true;
        if (!setValidity || typeof setValidity !== 'function') {
            return;
        }
        // save not allow while editting or adding a new row
        if (editIndex >= 0 || newRow) {
            isValid = false;
        } else if (minEntries && _.isEmpty(fields) || fields.length < minEntries) {
            isValid = false;
        }

        setValidity(isValid);
    }

    validateField = (val) => {
        const {fields, editIndex} = this.state;
        const {fieldType} = this.props;
        let tempFileds = fields.concat();
        let isValid = true;

        switch (fieldType) {
            case FIELD_TYPE.DOMAIN_NAME:
                isValid = isValidHostName(val);
                break;
            case FIELD_TYPE.IP:
            default:
                isValid = isIpValid(val);
        }
        if (!isValid) {
            this.setState({fieldError: {message: LABELS[(fieldType || 'Ip') + 'NotValid'], status: true}});
            return isValid;
        }

        if (editIndex >= 0) {
            tempFileds.splice(editIndex, 1);
        }
        if (tempFileds.includes(val)) {
            isValid = false;
            this.setState({fieldError: {message: LABELS.duplicatedEntries, status: true}});
            return isValid;
        }

        this.setState({fieldError: {message: '', status: false}});
        return isValid;
    }

    renderRows = () => {
        const {fields, editIndex, fieldError} = this.state;
        if (fields) {
            return fields.map((f, i) => {
                if (i === editIndex) {
                    return (
                        <div key={i} className="edit-form">
                            <div className="list row">
                                <div className="edit-input">
                                    <Input
                                        type="text"
                                        value={fields[i]}
                                        onChange={(e) => this.handleChange(e, i)}
                                        autoComplete="off"
                                        help={fieldError.status ? {message: fieldError.message, type: 'text-danger'} : null}
                                    />
                                </div>
                                <div className="actions-row">
                                    <span onClick={() => this.saveRow(i)} className="icon-check actionable icon-small" title={'ok'} />
                                    <span>{NBSP}</span>
                                    <span onClick={() => this.cancelRow(i)} className="icon-close actionable icon-small" title={'cancel'} />
                                </div>
                            </div>
                        </div>
                    );
                }

                return (
                    <div key={i} className="edit-form">
                        <div className="list row">
                            <div className="editlist">{fields[i]}</div>
                            <div className="actions-row">
                                <span onClick={() => this.editRow(i)} className="icon-edit actionable icon-small" title={'edit'} />
                                <span>{NBSP}</span>
                                <span onClick={() => this.deleteRow(i)} className="icon-exit-contain actionable icon-small" title={'remove'} />
                            </div>
                        </div>
                    </div>
                );
            });
        }
    }

    renderNewRow = () => {
        const {newRowValue} = this.state;
        return (
            <div className="edit-form">
                <div className="list row">
                    <div className="edit-input">
                        <Input
                            type="text"
                            value={newRowValue}
                            onChange={(e) => this.handleChange(e, -1)}
                            autoComplete="off"
                            help={this.state.fieldError.status ? {message: this.state.fieldError.message, type: 'text-danger'} : null}
                        />
                    </div>
                    <div>
                        <span onClick={() => this.saveRow(-1)} className="icon-check actionable icon-small" title={'ok'} />
                        <span>{NBSP}</span>
                        <span onClick={() => this.cancelRow(-1)} className="icon-close actionable icon-small" title={'cancel'} />
                    </div>
                </div>

            </div>
        );
    }

    render() {
        const {header, subHeader, actionLabel, minEntries} = this.props;
        const {newRow} = this.state;
        let headerLabels = [header];
        if (minEntries) {
            headerLabels.push(<span className="text-danger"> *</span>);
        }

        return (
            <div className="form-group children-objects-field" >
                <label className="property-label">{headerLabels}</label>
                <div className="hostnamelbl children-objects-table">
                    <label className="edit-property-label">{subHeader}</label>
                    {this.renderRows()}
                    {newRow ? this.renderNewRow() : null}
                </div>

                {!newRow ? <div className="add-item">
                    <span onClick={this.addRow} className="actions-row">
                        <span className="icon-add-contain icon-small" /> {actionLabel}
                    </span>
                </div> : null}
            </div>
        );
    }
}

EditableTableList.FIELD_TYPE = FIELD_TYPE;

EditableTableList.propTypes = {
    addRow: PropTypes.func,
    deleteRow: PropTypes.func,
    reformatData: PropTypes.func,
    beforeSaveRow: PropTypes.func,
    saveRow: PropTypes.func,
    editRow: PropTypes.func,
    renderRows: PropTypes.func,
    renderRow: PropTypes.func,
    fieldData: PropTypes.array,
    header: PropTypes.string,
    subHeader: PropTypes.string,
    actionLabel: PropTypes.string,
    id: PropTypes.any,
    getSetUpValue: PropTypes.func,
    fieldType: PropTypes.string,
    setValidity: PropTypes.func,
    minEntries: PropTypes.number
};

EditableTableList.defaultProps = {
    editable: true,
    deletable: true,
    disabled: false,
    submitDiff: false,
    showLabel: true
};

export {EditableTableList};
