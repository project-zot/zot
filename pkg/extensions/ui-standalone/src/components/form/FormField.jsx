import React from 'react';
import _ from 'lodash';
import PropTypes from 'prop-types';

const fieldTypes = {
};

const defaultFields = {
};

class FormField extends React.Component {
    render() {
        const {property, formApi, obj, options, fieldType, ignoreRnValidation = typeof this.props.obj.dn === 'undefined' && this.props.obj.status !== 'modified', apiFormat, ...rest} = this.props;
        const id = apiFormat ? obj._class + '.attributes.' + property : property;
        const objDescriptor = obj._classDescriptor;

        let Field;
        // type can be forcefully overridden
        if (typeof fieldType !== 'undefined') {
            Field = fieldTypes[fieldType];
        } else if (property === 'descr' && this.props.className !== 'input--compressed') {
            // all descriptions use a textArea unless overridden
            Field = '';
        } else {
            // use the default one
            Field = _.get(defaultFields, _.get(objDescriptor[property], 'type', 'default'), defaultFields.default);
        }

        const value = obj[property];
        let disabled = false;
        if (!ignoreRnValidation) {
            if (_.get(objDescriptor, '_rnProps', []).includes(property) && typeof value !== 'undefined') {
                // rn props are not editable
                disabled = true;
            }
        }
        // this is for custom UI fields that don't actually belong to the MO class
        const {descriptor, ...restWithoutDescriptor} = {...rest};
        let propertyDescriptor = objDescriptor[property] || descriptor;

        return <Field key={id} id={id} disabled={disabled} formApi={formApi} descriptor={propertyDescriptor} value={value} options={options} {...restWithoutDescriptor}/>;
    }
}

FormField.defaultProps = {
    apiFormat: true
};

FormField.propTypes = {
    property: PropTypes.any,
    formApi: PropTypes.any,
    options: PropTypes.any,
    fieldType: PropTypes.any,
    ignoreRnValidation: PropTypes.any,
    obj: PropTypes.any,
    apiFormat: PropTypes.any,
    className: PropTypes.string,
};

export {FormField};
