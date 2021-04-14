import React from 'react';
import PropTypes from 'prop-types';
import _ from 'lodash';
import './ProgressSteps.scss';

class ProgressSteps extends React.Component {
    constructor(props) {
        super(props);
    }

    renderSteps = (steps) => {
        return steps.map((item, i) => {
            let key = 'grid-cell-' + i;
            let className = '';
            let iconSize = 'icon-xs';
            if (i === this.props.currentStep) {
                className = '-selected';
                iconSize = 'icon-small';
            }

            return (
                <div key= {i} className="flex flex-center flex-wrap">
                    <div className={'step-content' + className}>
                        <div className="flex flex-center flex-wrap">
                            <div className="step-icon">
                                <span className={item.icon + ' ' + iconSize}/>
                            </div>
                            <div className="step-title">
                                <span>{item.title}</span>
                            </div>
                        </div>
                    </div>
                    { i < steps.length - 1 ? <span className="connecting-line"/> : null}
                </div>

            );
        });
    };

    render() {
        return (
            <div className="col-xs-12">
                <div className="flex flex-left flex-wrap">
                    {this.renderSteps(this.props.steps)}
                </div>
            </div>
        );
    }
}

ProgressSteps.defaultProps = {
    steps: [],
    currentStep: 0
};

ProgressSteps.propTypes = {
    currentStep: PropTypes.number,
    steps: PropTypes.array,
};

export {ProgressSteps};
