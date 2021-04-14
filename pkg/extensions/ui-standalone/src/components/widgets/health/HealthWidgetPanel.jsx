import React from 'react';
import {WidgetPanel} from '../panel/WidgetPanel';
import {HealthWidget} from './HealthWidget';
import LABELS from '../../../strings';

import './HealthWidgetPanel.scss';

class HealthWidgetPanel extends React.Component {
    constructor(props) {
        super(props);
        this.state = {hide: false};
    }

    ApiLoadError = () => {
        // show grey instead of disabling for now, since most objects need health added by backend
        // this.setState({hide: true});
    };

    render() {
        if (this.state.hide) {
            return null;
        }
        return (
            <WidgetPanel title={LABELS.health}>
                <HealthWidget {...this.props} noApiCallback={this.ApiLoadError}/>
            </WidgetPanel>
        );
    }
}

export {HealthWidgetPanel};
