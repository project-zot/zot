import React from 'react';
import {HealthBadgeIcon} from '../summarypane/HealthBadgeIcon';

import './HealthWidget.scss';

class HealthWidget extends React.Component {
    constructor(props) {
        super(props);
        // this.data = this.props.data;
        this.state = {loading: false};
    }

    render() {
        let classes = ['health-widget'];

        const healthScore = 'Healthy';
        let healthLabel = 'na';

        if (typeof healthScore !== 'undefined') {
            switch (true) {
                case healthScore <= 20:
                    healthLabel = 'Critical';
                    classes.push('critical');
                    break;
                case healthScore <= 50:
                    healthLabel = 'Major';
                    classes.push('major');
                    break;
                case healthScore <= 80:
                    healthLabel = 'Minor';
                    classes.push('minor');
                    break;
                default:
                    healthLabel = 'Healthy';
                    classes.push('healthy');
            }
        } else if (this.isCloudObject) {
            // cloud objects somehow are considered ok if there is no health info
            healthLabel = 'Healthy';
            classes.push('healthy');
        }
        return (
            <div className={classes.join(' ')}>
                <span className="badge"><HealthBadgeIcon value={healthScore} /></span>
                <span className="count">{healthLabel}</span>
            </div>
        );
    }
}

export {HealthWidget};
