import React from 'react';
import PropTypes from 'prop-types';
import _ from 'lodash';
import {FormField} from './FormField';
import './FormSection.scss';

class FormSection extends React.Component {
    renderFields() {
        const {obj, formApi, fields} = this.props;

        if (typeof obj === 'undefined' || typeof formApi === 'undefined' || typeof fields === 'undefined') {
            return this.props.children;
        }

        return fields.map((property) => {
            if (_.isString(property)) {
                return (<FormField key={property} formApi={formApi} obj={obj} property={property}/>);
            }
            const {name, ...rest} = property;
            return (<FormField key={name} formApi={formApi} obj={obj} property={name} {...rest}/>);
        });
    }

    render() {
        return (
            <div className="form-section">
                <header>
                    <h5>{this.props.title}</h5>
                </header>
                <main className="panel panel--bordered">
                    {this.props.disabled ? <div className="disabled-overlay"/> : null}
                    {this.renderFields()}
                </main>
            </div>
        );
    }
}

FormSection.propTypes = {
    obj: PropTypes.any,
    fields: PropTypes.array,
    formApi: PropTypes.any,
    children: PropTypes.node,
    title: PropTypes.string,
    disabled: PropTypes.bool,
};

export {FormSection};
