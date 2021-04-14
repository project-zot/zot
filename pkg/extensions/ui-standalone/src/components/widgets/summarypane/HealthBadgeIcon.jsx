import React from 'react';
import PropTypes from 'prop-types';
import _ from 'lodash';

import {HEALTH_SEVERITY, HEALTH_LABEL, HEALTH_SEVERITY_MAP} from '../../../constants';

import iconHealthCritical from '../../../static/icons/icon-health-critical.svg';
import iconHealthMajor from '../../../static/icons/icon-health-major.svg';
import iconHealthMinor from '../../../static/icons/icon-health-minor.svg';
import iconHealthOk from '../../../static/icons/icon-health-ok.svg';
import iconHealthUnknown from '../../../static/icons/icon-health-unknown-dark.svg';
import iconHealthWhite from '../../../static/icons/icon-health-white.svg';

import './HealthBadgeIcon.scss';

class HealthBadgeIcon extends React.Component {
    static Severity = HEALTH_SEVERITY;

    static Theme = {
        BASIC: 'basic',
        HALO: 'halo'
    };

    getIconBySeverity(severity) {
        const {theme} = this.props;

        switch (severity) {
            case HealthBadgeIcon.Severity.CRITICAL:
                return iconHealthCritical;
            case HealthBadgeIcon.Severity.MAJOR:
                return iconHealthMajor;
            case HealthBadgeIcon.Severity.MINOR:
                return iconHealthMinor;
            case HealthBadgeIcon.Severity.OK:
                return iconHealthOk;
            case HealthBadgeIcon.Severity.UNKNOWN:
            default:
                return iconHealthUnknown;
        }
    }

    getSeverityFromValue(value) {
        switch (true) {
            case value <= 20:
                return HealthBadgeIcon.Severity.CRITICAL;
            case value <= 50:
                return HealthBadgeIcon.Severity.MAJOR;
            case value <= 80:
                return HealthBadgeIcon.Severity.MINOR;
            case value <= 100:
                return HealthBadgeIcon.Severity.OK;
            default:
                return HealthBadgeIcon.Severity.UNKNOWN;
        }
    }

    render() {
        const {value, severity, status, showLabel, showBackground, theme, divSize} = this.props;
        const severityValue = typeof value !== 'undefined' ? this.getSeverityFromValue(value) : severity || status && HEALTH_SEVERITY_MAP[status.toLowerCase()];
        const icon = this.getIconBySeverity(severityValue);

        let content = (<img className="health-badge-icon" src={icon} title={'value'}/>);
        if (showLabel || theme === HealthBadgeIcon.Theme.HALO) {
            content = (
                <div className={`cui health-icon-container bg-${severityValue} theme-${theme}`} style={{width: divSize, height: divSize}}>
                    <img className="health-badge-icon" src={icon} title={value}/>
                    {showLabel && <span className="health-label">{HEALTH_LABEL[severityValue]}</span>}
                </div>
            );
        } else if (showBackground) {
            content = (
                <div className={`cui health-icon-container bg-${severityValue}`} style={{display: 'flex', width: divSize, height: divSize}}>
                    <img className="health-badge-icon" src={icon} title={value}/>
                </div>
            );
        }

        return content;
    }
}

HealthBadgeIcon.defaultProps = {
    theme: HealthBadgeIcon.Theme.BASIC,
    showLabel: false,
    showBackground: false,
    divSize: 34,
};

HealthBadgeIcon.propTypes = {
    value: PropTypes.string,
    severity: PropTypes.oneOf(_.toArray(HealthBadgeIcon.Severity)),
    status: PropTypes.string,
    theme: PropTypes.oneOf(_.toArray(HealthBadgeIcon.Theme)),
    showLabel: PropTypes.bool,
    showBackground: PropTypes.bool,
    divSize: PropTypes.number,
};

export {HealthBadgeIcon};
