import React from 'react';
import {DangerAlert, WarningAlert, InfoAlert, Icon} from 'blueprint-react';
import {get, isEmpty, isEqual} from 'lodash';
import PropTypes from 'prop-types';
import './FormError.scss';

const ERROR_CODE = {
    INFO: 'info',
    WARNING: 'warning',
    ERROR: 'error'
};

class FormError extends React.Component {
    // this could contain some mapping between error code and text, for now just render the error text
    constructor(props) {
        super(props);
        this.errorContainer = React.createRef();
        this.state = {
            errorExpanded: false
        };
    }

    componentDidUpdate(prevProps) {
        if (this.props.focus && !isEqual(this.props.error, prevProps.error) && this.errorContainer.current) {
            this.errorContainer.current.scrollIntoView();
        }
    }

    onErrorExpandToggle = () => {
        console.log('error expanded: ' + this.state.errorExpanded);
        this.setState({errorExpanded: !this.state.errorExpanded});
    }

    render() {
        const {error, className} = this.props;
        const {errorExpanded} = this.state;
        let errorCode = get(error, 'code') || '';
        let classes = ['form-error'];
        let errorDetail = error && error.detail;
        let errorText, detailComponent;
        let AlertCmp;

        if (!isEmpty(errorDetail)) {
            errorDetail.forEach((detail) => {
                const severity = detail && detail.Severity || '';
                switch (severity.toLowerCase()) {
                    case 'minor':
                    case 'major':
                        if (errorCode !== ERROR_CODE.ERROR) {
                            errorCode = ERROR_CODE.WARNING;
                        }
                        break;
                    case 'critical':
                        errorCode = ERROR_CODE.ERROR;
                        break;
                    default:
                }
            });
        }
        if (errorCode) {
            switch (errorCode.toLowerCase()) {
                case ERROR_CODE.INFO:
                    AlertCmp = InfoAlert;
                    break;
                case ERROR_CODE.WARNING:
                    AlertCmp = WarningAlert;
                    break;
                case ERROR_CODE.ERROR:
                default:
                    AlertCmp = DangerAlert;
            }
        }

        if (!AlertCmp) {
            return null;
        }
        if (className) {
            classes.push(className);
        }
        if (!isEmpty(errorDetail)) {
            if (errorExpanded) {
                detailComponent =
                (<div className="error-detail">
                    {errorDetail.map((detailItem, index) => {
                        let content = '';
                        let icon, iconClass;
                        if (typeof detailItem === 'string') {
                            content = detailItem;
                        } else if (typeof detailItem.Message === 'string') {
                            content = detailItem.Message;
                            switch (detailItem.Severity) {
                                case 'minor':
                                    icon = Icon.TYPE.WARNING;
                                    iconClass = 'minor';
                                    break;
                                case 'major':
                                    icon = Icon.TYPE.WARNING;
                                    iconClass = 'major';
                                    break;
                                case 'critical':
                                    icon = Icon.TYPE.ERROR;
                                    break;
                                default:
                            }
                        } else {
                            content = detailItem;
                        }
                        return (
                            <div key={'detail-content-' + index} className="detail-content">
                                {icon ? <Icon type={icon} className={iconClass}/> : ''}
                                {content}
                            </div>
                        );
                    })
                    }
                </div>);
                classes.push('error-expanded');

                errorText = <div>{error.text} <a onClick={this.onErrorExpandToggle}>Collapse</a> to hide.</div>;
            } else {
                errorText = <div>{error.text} <a onClick={this.onErrorExpandToggle}>Expand</a> to see details.</div>;
            }
        } else {
            errorText = error.text;
        }

        return (
            <div className={classes.join(' ')} ref={this.errorContainer}>
                <AlertCmp>
                    <div>
                        <div>{errorText}</div>
                        <div>{detailComponent}</div>
                    </div>
                </AlertCmp>
            </div>
        );
    }
}

FormError.ERROR_CODE = ERROR_CODE;

FormError.propTypes = {
    error: PropTypes.object,
    className: PropTypes.string,
    focus: PropTypes.bool
};

FormError.defaultProps = {
    focus: true,
};

export {FormError};
