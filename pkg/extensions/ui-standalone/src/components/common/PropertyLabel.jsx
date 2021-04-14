import React from 'react';
import PropTypes from 'prop-types';
import './PropertyLabel.scss';
import _ from 'lodash';
const ASTERISK = '*';
import {connect} from 'react-redux';
import {withRouter} from 'react-router';

class PropertyLabel extends React.Component {
    constructor(props) {
        super(props);
        // the location of a label is decided at construction time, and will never change
        // highest non minimized screen is the current one by definition at construction time
        const activeScreenId = _.get(_.filter(props.openedScreens, (s) => !s.minimized).pop(), 'type');

        // if there is no such thing, then this label belongs in a page, use the router location
        this.location = activeScreenId || props.location.pathname;

        this.state = {
            showToolTip: false
        };
        this.nodeRef = React.createRef();
    }

    getConnectionNode() {
        return this.nodeRef.current;
    }

    onNodeClick(e) {
        if (this.props.onClick) {
            this.props.onClick(e);
        }
    }

    render() {
        const {moClass, property, label, className, mandatory, htmlFor, tooltipText = false} = this.props;
        const descriptor = typeof moClass === 'string' ? 'getClassDescriptor(moClass)' : {};
        const labelTxt = !label && _.get(descriptor, `${property}.label`) ? descriptor[property].label : label;
        const mandatoryMarker = mandatory ? <span className="text-danger"> {ASTERISK}</span> : '';

        let labelId = this.props.htmlFor ? this.props.htmlFor.replace('.attributes.', '.') : moClass + '.' + property;
        if (this.location) {
            labelId = this.location + '/' + labelId;
        }

        const tooltip = tooltipText !== false ? tooltipText : '_.get(TOOLTIP_STRINGS, labelId, false)';

        let classes = ['property-label'];
        if (className) {
            classes.push(className);
        }

        if (!labelTxt) {
            return null;
        }

        if (tooltip !== false) {
            return (
                <React.Fragment>
                    <label id={labelId} htmlFor={htmlFor} className={classes.join(' ')}>
                        {labelTxt}
                    </label>
                    {mandatoryMarker}
                </React.Fragment>
            );
        }
        return (
            <div>
                <label id={labelId} htmlFor={htmlFor} className={classes.join(' ')}>{labelTxt}</label>
                {mandatoryMarker}
            </div>);
    }
}

PropertyLabel.propTypes = {
    openedScreens: PropTypes.array,
    location: PropTypes.object,
    onClick: PropTypes.func,
    moClass: PropTypes.string,
    property: PropTypes.string,
    label: PropTypes.string,
    className: PropTypes.string,
    mandatory: PropTypes.bool,
    htmlFor: PropTypes.string,
    tooltipText: PropTypes.string,
};

const mapStateToProps = (state) => ({
    openedScreens: state.app.openedScreens
});

PropertyLabel = connect(mapStateToProps, {})(withRouter(PropertyLabel));
export {PropertyLabel};
