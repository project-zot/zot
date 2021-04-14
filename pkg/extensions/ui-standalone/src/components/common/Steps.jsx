import React from 'react';
import PropTypes from 'prop-types';

const STEPS = 'ui-steps',
    SMALL = 'ui-steps--small',
    STEP = 'ui-step',
    STEP_ICON = 'step__icon',
    STEP_LABEL = 'step__label',
    ACTIVE = 'active',
    VISITED = 'visited',
    EMPTY = '',
    SPACE = ' ';

class Steps extends React.Component {
    cssBaseClass = [STEPS];

    componentDidMount() {
        this.cssBaseClass.push(this.props.orientation, this.props.theme);
    }

    renderStep(label, number, active, visited) {
        let classes = [STEP];

        if (active) {
            classes.push(ACTIVE);
        } else if (visited) {
            classes.push(VISITED);
        }

        return (<div key={`${number}-${active}`} className={classes.join(' ')}>
            <div className={STEP_ICON}>{number}</div>
            <div className={STEP_LABEL}>{label}</div>
        </div>);
    }

    render() {
        const {steps, currentStep} = this.props;

        const items = steps.map((value, index) => {
            let number = index + 1;
            let active = currentStep === index;
            let visited = currentStep > index;

            return this.renderStep(value, number, active, visited);
        });

        return (<div className={this.cssBaseClass.join(SPACE)}>{items}</div>);
    }
}

Steps.ORIENTATION = {
    HORIZONTAL: EMPTY,
    VERTICAL: `${STEPS}--vertical`
};

Steps.THEME = {
    DEFAULT: EMPTY,
    ALT: `${STEPS}--alt`,
    INFO: `${STEPS}--info`,
    SUCCESS: `${STEPS}--success`,
    WARNING: `${STEPS}--warning`,
    DANGER: `${STEPS}--danger`
};

Steps.propTypes = {
    theme: PropTypes.oneOf(Object.values(Steps.THEME)),
    orientation: PropTypes.oneOf(Object.values(Steps.ORIENTATION)),
    steps: PropTypes.array,
    currentStep: PropTypes.number
};

Steps.defaultProps = {
    orientation: Steps.ORIENTATION.HORIZONTAL,
    steps: [],
    currentStep: 0,
    theme: Steps.THEME.DEFAULT
};

class SmallSteps extends Steps {
    cssBaseClass = [STEPS, SMALL];
}

SmallSteps.ORIENTATION = Steps.ORIENTATION;

SmallSteps.THEME = Steps.THEME;

export {Steps, SmallSteps};
