import React from 'react';
import PropTypes from 'prop-types';
import _ from 'lodash';
import {Link} from 'blueprint-react';
// import {ObjectLink} from 'src/components/common/ObjectLink';

const NBSP = '\u00A0';

class Property extends React.Component {
    constructor() {
        super();

        this.state = {
            hideArrayElements: true
        };
    }

    // this is basically a formatter, leaving it as a component in case we want to have images or things like that for some properties
    render() {
        const {value, propDescriptor} = this.props;
        let propValue = value;

        if (typeof propDescriptor !== 'undefined') {
            switch (propDescriptor.type) {
                case 'boolean':
                    if (typeof propDescriptor.trueValue !== 'undefined' && typeof propDescriptor.falseValue !== 'undefined') {
                        if (value === propDescriptor.trueValue) {
                            propValue = propDescriptor.shownValue || propDescriptor.trueValue;
                        } else {
                            propValue = propDescriptor.shownFalseValue || propDescriptor.falseValue;
                        }
                    } else {
                        // trueValue/faseValue are not defined, just show the value as plain string
                        propValue = value;
                    }
                    break;
                case 'bitmask':
                    if (typeof value !== 'undefined' && value !== '') {
                        propValue = value.split(',').map((v) => {
                            return _.get(_.find(propDescriptor.options, {value: v}), 'label', v);
                        }).join(', ');
                    } else {
                        propValue = '';
                    }
                    break;
                case 'enum':
                    if (typeof value !== 'undefined' && value !== '') {
                        propValue = _.get(_.find(propDescriptor.options, (item) => item.value === value), 'label', value);
                    } else {
                        propValue = '';
                    }
                    break;
                case 'array':
                    if (propValue.length > 1) {
                        if (this.state.hideArrayElements) {
                            return (
                                <ul className="list">
                                    <span>{propValue[0]}</span>
                                    <div><Link onClick={() => {
                                        this.setState({hideArrayElements: false});
                                    }}>{propValue.length - 1 + ' more'}</Link></div>
                                </ul>
                            );
                        }
                        return (
                            <ul className="list">
                                {
                                    propValue.map((data, i) => <div key={i}><span>{data}</span></div>)
                                }
                            </ul>
                        );
                    }
                    return (
                        <span>{propValue[0]}</span>
                    );

                case 'namedPropertyLink':
                    return <div>ObjectLink</div>;
                default:
                    propValue = value;
            }
        }

        if (propValue === '') {
            propValue = NBSP;
        }

        return (
            <span>{propValue}</span>
        );
    }
}

Property.propTypes = {
    value: PropTypes.string,
    propDescriptor: PropTypes.string,
};

export {Property};
