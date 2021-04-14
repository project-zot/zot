import React from 'react';
import {HashRouter as Router, Route, Switch, Redirect} from 'react-router-dom';
import PropTypes from 'prop-types';

import {connect} from 'react-redux';
import {appActions} from './state/app/action';

import {Sidebar, Spinner} from 'blueprint-react';
import {Header} from './common/layout/Header';
import {Images} from './common/pages/infrastructure/index';
import {ScreensRenderer} from './components/screen/ScreensRenderer';
import {ModalsRenderer} from './components/modals/ModalsRenderer';

import {SCREEN_TYPES, DETAILS_SCREEN_PREFIX, SETUP_SCREEN_PREFIX} from './config/screens-config';
import {MODAL_TYPES} from './config/modals-config';
import {SUMMARY_PANE_TYPES} from './config/summary-config';
import {PATHS, SIDEBAR_ITEMS} from './config/route-config';

import './App.scss';

const PATH_COMPONENTS = {
    images: Images,
};

class App extends React.Component {
    constructor(props, context) {
        super(props, context);

        this.state = {
            auth: false,
        };

        this.routes = Object.keys(PATH_COMPONENTS).map((key) => <Route key={`${key}`} path={PATHS[key]} component={PATH_COMPONENTS[key]} />);
    }

    componentDidMount() {

    }

    render() {
        const {
            openedScreens,
            closeScreen,
            minimizeScreen,
            saveScreenTitle,
            visibleSummaryPane,
            closeSummaryPane,
            visibleObjectsListPane,
            closeObjectsListPane,
            openedModals,
            closeModal,
            session,
            isSchemas,
            clusterStatus
        } = this.props;

        let rootClasses = 'app-container';
        let mainContentClasses = 'main-content-wrapper';
        let sidebarMenu = [];
        let sidebarCmp;

        sidebarCmp = <Sidebar title={''} items={SIDEBAR_ITEMS} expanded={true} />;

        return (
            <Router>
                <div className={rootClasses}>
                    <ScreensRenderer openedScreens={openedScreens} screenComponents={SCREEN_TYPES} onClose={closeScreen} onMinimize={minimizeScreen} saveTitle={saveScreenTitle} detailsPrefix={DETAILS_SCREEN_PREFIX} />
                    <ModalsRenderer onClose={closeModal} openedModals={openedModals} modalComponents={MODAL_TYPES} />
                    {sidebarCmp}
                    <div className={mainContentClasses}>
                        <Header />
                        <main>
                            <div className="routed-content">
                                <Switch>
                                    <Route exact path="/" render={() => <Redirect to={'/images'} />} />
                                    {this.routes}
                                </Switch>
                            </div>
                        </main>
                    </div>
                </div>
            </Router>
        );
    }
}

App.propTypes = {
    showSidebar: PropTypes.bool,
    openedScreens: PropTypes.array,
    showCreateMenu: PropTypes.bool,
    saveScreenTitle: PropTypes.func,
    minimizeScreen: PropTypes.func,
    closeScreen: PropTypes.func,
    visibleSummaryPane: PropTypes.object,
    closeSummaryPane: PropTypes.func,
    visibleObjectsListPane: PropTypes.object,
    closeObjectsListPane: PropTypes.func,
    openedModals: PropTypes.array,
    closeModal: PropTypes.func,
    openScreen: PropTypes.any,
    setClusterData: PropTypes.func,
    session: PropTypes.object,
    isSchemas: PropTypes.bool,
    setClusterStatus: PropTypes.func,
    clusterStatus: PropTypes.object
};

const mapStateToProps = (state) => ({
    showCreateMenu: state.app.showCreateMenu,
    openedScreens: state.app.openedScreens,
    visibleSummaryPane: state.app.visibleSummaryPane,
    visibleObjectsListPane: state.app.visibleObjectsListPane,
    openedModals: state.app.openedModals,
    session: state.session,
    clusterStatus: state.app.clusterStatus
});

export default connect(mapStateToProps, appActions.merge([appActions.LAYOUT_ACTIONS, appActions.SCREEN_ACTIONS, appActions.SUMMARY_PANE_ACTIONS, appActions.MODAL_ACTIONS, appActions.GLOBAL_DATA_ACTIONS]))(App);
