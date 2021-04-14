import React from 'react';
import PropTypes from 'prop-types';
import _ from 'lodash';
import onClickOutside from 'react-onclickoutside';
import {Loader} from 'blueprint-react';
import {GenericSummaryPane} from '../summary-pane/GenericSummaryPane';

// Redux integration
import {connect} from 'react-redux';
import {appActions} from '../../state/app/action';

import './SummaryPane.scss';

class SummaryPane extends React.Component {
    constructor(props) {
        super(props);
        this.state = {loading: false};
    }

    openDetails(obj) {
        this.props.openDetailsScreen(this.props.data.type, obj.serialNumber || obj.name, obj);
    }

    render() {
        const {summaryPaneTypes, screenComponents, detailsPrefix, data} = this.props;
        const objType = data && data.type;
        const obj = _.get(this.props, 'data.obj') || this.obj;
        if (typeof this.props.data === 'undefined') {
            return null;
        }
        if (typeof obj === 'undefined') {
            return (
                <div className="summary-pane">
                    <Loader/>
                </div>
            );
        }

        const SummaryPaneContent = summaryPaneTypes && objType && summaryPaneTypes[objType] || GenericSummaryPane;
        const detailScreen = screenComponents && detailsPrefix && screenComponents[detailsPrefix + objType];
        let closeIcon = null;

        if (typeof this.props.onClose === 'function') {
            closeIcon = <span className="link icon-close icon-small" style={{fontSize: 17}} onClick={this.props.onClose}/>;
        }

        return (
            <div className="summary-pane">
                <div className="summary-pane-buttons">
                    {
                        detailScreen ?
                            <span className="link icon-jump-out icon-small" onClick={()=>{
                                this.openDetails(obj);
                            }}/>
                            : ''
                    }
                    {closeIcon}
                </div>
                <SummaryPaneContent obj={obj}/>
            </div>
        );
    }

    handleClickOutside = () => {
        if (typeof this.props.onClose === 'function') {
            this.props.onClose();
        }
    };
}

SummaryPane.propTypes = {
    openDetailsScreen: PropTypes.func,
    onClose: PropTypes.func,
    data: PropTypes.object,
    summaryPaneTypes: PropTypes.any,
    screenComponents: PropTypes.object,
    detailsPrefix: PropTypes.string
};

SummaryPane = connect(() => ({}), appActions.merge([appActions.SCREEN_ACTIONS, appActions.MODAL_ACTIONS]))(onClickOutside(SummaryPane));
export {SummaryPane};
