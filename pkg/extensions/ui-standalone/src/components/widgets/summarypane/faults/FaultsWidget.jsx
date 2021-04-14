import React from 'react';
import {Loader} from 'blueprint-react';
import _ from 'lodash';
import './FaultsWidget.scss';

class FaultsWidget extends React.Component {
    constructor(props) {
        super(props);
        this.state = {
            // loading: typeof this.props.data === 'undefined'
        };
    }

    render() {
        const critical = 0;
        const major = 0;
        const minor = 0;
        const warning = 0;
        const zeroValueClass = 'zero-values';
        const severityClasses = {
            CRITICAL: 'faults-level-critical' + (critical === 0 ? ' ' + zeroValueClass : ''),
            MAJOR: 'faults-level-major' + (major === 0 ? ' ' + zeroValueClass : ''),
            MINOR: 'faults-level-minor' + (minor === 0 ? ' ' + zeroValueClass : ''),
            WARNING: 'faults-level-warning' + (warning === 0 ? ' ' + zeroValueClass : '')
        };

        return (
            <div className="faults-widget">
                <div className="labels">
                    <div className={severityClasses.CRITICAL}>{'critical'}</div>
                    <div className={severityClasses.MAJOR}>{'major'}</div>
                    <div className={severityClasses.MINOR}>{'minor'}</div>
                    <div className={severityClasses.WARNING}>{'warning'}</div>
                </div>
                <div className="counters">
                    <div className={severityClasses.CRITICAL}>{critical}</div>
                    <div className={severityClasses.MAJOR}>{major}</div>
                    <div className={severityClasses.MINOR}>{minor}</div>
                    <div className={severityClasses.WARNING}>{warning}</div>
                </div>
            </div>
        );
    }
}

export {FaultsWidget};
