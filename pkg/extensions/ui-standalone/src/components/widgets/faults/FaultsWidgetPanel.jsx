import React from 'react';
import {WidgetPanel} from '../../../components/widgets/panel/WidgetPanel';
import {FaultsWidget} from '../summarypane/faults/FaultsWidget';
import LABELS from '../../../strings';

// Redux integration
import {connect} from 'react-redux';
import {appActions} from '../../../state/app/action';

import './FaultsWidgetPanel.scss';

class FaultsWidgetPanel extends React.Component {
    constructor(props) {
        super(props);
        this.state = {hide: false};
    }

    ApiLoadError = () => {
        this.setState({hide: true});
    };

    render() {
        if (this.state.hide) {
            return null;
        }
        return (
            <WidgetPanel title={LABELS.faults}>
                <FaultsWidget {...this.props} noApiCallback={this.ApiLoadError}/>
            </WidgetPanel>
        );
    }
}

FaultsWidgetPanel = connect(() => ({}), appActions.MODAL_ACTIONS)(FaultsWidgetPanel);
export {FaultsWidgetPanel};
