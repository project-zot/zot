import React from 'react';
import {HealthBadgeIcon} from '../summarypane/HealthBadgeIcon';

class HealthBadge extends React.Component {
    constructor(props) {
        super(props);
    }

    render() {
        return (
            <HealthBadgeIcon {...this.props}/>
        );
    }
}

export {HealthBadge};
