import React from 'react';
import PropTypes from 'prop-types';
import {Button, Checkbox, Icon} from 'blueprint-react';
import {isEmpty, noop} from 'lodash';
import {connect} from 'react-redux';

import {setupActions} from '../../../state/setup/action';
import {appActions} from '../../../state/app/action';
import LABELS from '../../../strings';
import api from '../../../common/utils/api';
import {uiUtils} from '../../../common/utils/ui-utils';

import './Splash.scss';

const CLASSES = {
    MAIN: 'splash',
    BACKDROP: 'splash-backdrop'
};

const SPLASH_URLS = {
    PRODUCT_PAGE: 'https:\//www.cisco.com/c/en/us/products/collateral/data-center-analytics/network-insights-data-center/datasheet-c78-742892.html',
    RELEASE_NOTES: 'https:\//www.cisco.com/c/en/us/td/docs/dcn/nd/2x/release-notes/cisco-nexus-dashboard-release-notes-201.html',
    USER_GUIDE: 'https:\//www.cisco.com/c/dam/en/us/td/docs/dcn/nd/2x/user-guide/cisco-nexus-dashboard-user-guide-2x.pdf',
    DEPLOYMENT_GIUDE: 'https:\//www.cisco.com/c/en/us/td/docs/dcn/nd/2x/deployment/cisco-nexus-dashboard-deployment-guide-2x.html',
    ONLINE_VIDEO: 'https:\//www.youtube.com/channel/UC-U0ud423cfgHls0bV2jxXw',
};

class Splash extends React.Component {
    constructor(props) {
        super(props);
        this.state = {
            doNotShowOnLogin: true,
            version: ''
        };
    }

    componentDidMount() {
        // get version
        api.get('/version.json')
            .then((response) => {
                if (response.data) {
                    this.setState({version: uiUtils.getVersionFromJson(response.data)});
                }
            });
    }

    handleChange = (event) => {
        if (!isEmpty(event)) {
            this.setState({doNotShowOnLogin: true});
        } else {
            this.setState({doNotShowOnLogin: false});
        }
    };

    handleSubmit = () => {
        const {doNotShowOnLogin} = this.state;
        localStorage.setItem('doNotShowOnLogin', doNotShowOnLogin);
        this.props.closeScreen();
    };

    render() {
        return (
            <div className={CLASSES.MAIN}>
                <div className={CLASSES.BACKDROP} />
                <div className="splash-content hero hero__content hero--vibblue">
                    <header>
                        <h2>{LABELS.splashTitle + LABELS.appTitle}</h2>
                        <h6 className="versionTxt">{`${LABELS.whatsNewIn} ${this.state.version}`}</h6>
                        <Icon type={Icon.TYPE.STAR} />
                        <p className="new-features-label">{LABELS.newFeatures}</p>
                    </header>
                    <div className="row" >
                        <div className="col-sm-6">
                            <ul>
                                <li>{'Single Sign on for sites and services'}</li>
                                <li>{'Support for external authentication providers'}</li>
                                <li>{'Cloud ACI & DCNM site support'}</li>
                                <li>{'Role / persona based dashboard view'}</li>
                            </ul>
                        </div>
                        <div className="col-sm-6">
                            <ul>
                                <li>{'Highly available scale-out platform architecture'}</li>
                                <li>{'Service lifecycle management and orchestration'}</li>
                                <li>{'Single launchpad for sites and services'}</li>
                                <li>{'Service resource management and monitoring'}</li>
                            </ul>
                        </div>
                    </div>
                    <div className="row links">
                        <div className="col-sm-4">
                            <h4 style={{color: '#ffffff'}}>{LABELS.gettingStarted}</h4>
                            <ul>
                                <li>
                                    <a href={SPLASH_URLS.RELEASE_NOTES} target="_blank" rel="noopener noreferrer">{LABELS.releaseNotes}</a>
                                </li>
                                <li>
                                    <a href={SPLASH_URLS.ONLINE_VIDEO} target="_blank" rel="noopener noreferrer">{LABELS.onlineVideos}</a>
                                </li>
                            </ul>
                        </div>
                        <div className="col-sm-5">
                            <h4 style={{color: '#ffffff'}}>{LABELS.explore}</h4>
                            <ul>
                                <li>
                                    <a href={SPLASH_URLS.DEPLOYMENT_GIUDE} target="_blank" rel="noopener noreferrer">{LABELS.deploymentGuide}</a>
                                </li>
                                <li>
                                    <a href={SPLASH_URLS.USER_GUIDE} target="_blank" rel="noopener noreferrer">{LABELS.userGuide}</a>
                                </li>
                            </ul>
                        </div>
                        <div className="col-sm-3">
                            <h4 style={{color: '#ffffff'}}>{LABELS.support}</h4>
                            <ul>
                                <li>
                                    <a href={SPLASH_URLS.PRODUCT_PAGE} rel="noopener noreferrer" target="_blank">Product Page</a>
                                </li>
                            </ul>
                        </div>
                    </div>
                    <div className="row actions">
                        <div className="left-actions col-sm-4">
                            <Checkbox
                                name="doNotShowOnLogin"
                                label={LABELS.doNotShowOnLogin}
                                onChange={this.handleChange}
                                checked={true}
                            />
                        </div>
                        <div className="right-actions col-sm-8">
                            <Button type={Button.TYPE.WHITE} size={Button.SIZE.DEFAULT} onClick={this.handleSubmit}>{LABELS.getStarted}</Button>
                        </div>
                    </div>
                </div>
            </div>
        );
    }
}

Splash.defaultProps = {
    onCLick: noop
};

Splash.propTypes = {
    closeScreen: PropTypes.func,
};

// const mapStateToProps = (state) => ({
//     start: state.setup
// });

const mapDispatchToProps = (dispatch) => ({
    ...setupActions(dispatch),
    ...appActions.merge([appActions.SCREEN_ACTIONS, appActions.SUMMARY_PANE_ACTIONS, appActions.MODAL_ACTIONS])(dispatch)
});

Splash = connect(null, mapDispatchToProps)(Splash);

export {Splash};
