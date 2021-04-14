import React from 'react';
import {Label} from 'blueprint-react';
import _ from 'lodash';
import PropTypes from 'prop-types';
import './AnnotationBadge.scss';

const TEXT_REGEXP = /[ ,]+/;
const ORCHESTRATOR = 'orchestrator';
const ORCHESTRATOR_TABLE = {
    MSC: 'MSO'
};
class AnnotationBadge extends React.Component {
    getOrchestrator(annotation) {
        let orchestratorArray = [];
        orchestratorArray = annotation.split(TEXT_REGEXP).filter(text => text.indexOf(ORCHESTRATOR) !== -1);
        const firstValue = orchestratorArray[0] || '';
        return (firstValue.split(':')[1] || '').toUpperCase();
    }

    render() {
        const {obj, showLabel, className = ''} = this.props;
        const annotation = _.get(obj, 'annotation', '');
        let classes = 'annotation-container' + ' ' + className;
        const orchestrator = this.getOrchestrator(annotation);
        if (_.isEmpty(orchestrator)) {
            return null;
        }

        return (
            <div className={classes}>
                {showLabel ? <label className="property-label">{'LABELS.configuredBy'}</label> : null}
                <div>
                    <Label size={Label.SIZE.SMALL} theme={Label.THEME.INFO} bordered={Label.BORDERED.LABEL_BORDERED}>{ORCHESTRATOR_TABLE[orchestrator] || orchestrator}</Label>
                </div>
            </div>
        );
    }
}
AnnotationBadge.propTypes = {
    showLabel: PropTypes.bool
};

AnnotationBadge.defaultProps = {
    showLabel: false
};

export {AnnotationBadge};
