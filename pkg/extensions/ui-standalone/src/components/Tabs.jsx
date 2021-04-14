/* eslint react/no-children-prop: "off" */
import React from 'react';
import PropTypes from 'prop-types';
import _ from 'lodash';
import {Loader} from 'blueprint-react';
import {
    HashRouter as Router, Redirect,
    Route, Switch, Link
} from 'react-router-dom';

const CLASSES = {
    MAIN: 'tab',
    TABS: 'tabs',
    TABS_VERTICAL: 'tabs--vertical',
    VERTICAL: 'vertical',
    HEADING: 'tab__heading',
    ACTIVE: 'active',
    EXTERNAL_CLASS_NAME: 'cisco-ui-tabs'
};

import './Tabs.scss';

class Tabs extends React.Component {
    constructor(props) {
        super(props);

        let initialTab = _.findIndex(props.tabs, function(t) {
            return t.selected === true;
        });
        initialTab = initialTab === -1 ? 0 : initialTab;
        this.state = {
            openTab: initialTab
        };
        // TODO if we actually start using live tabs, might be useful to lazy load them
        if (props.live) {
            this.tabsContent = props.tabs.map((t) => {
                return t.content;
            });
        } else if (props.basePath) {
            let baseTab = this.props.tabs[initialTab];

            this.baseRoute = (<Redirect exact from={`${props.basePath}*`} to={`${props.basePath}/${baseTab.key}`} render={() => {
                return baseTab.content;
            }}/>);

            this.routes = props.tabs.map((t) => {
                return (<Route key={`${t.key}`} path={`${props.basePath}/${t.key}`} render={() => {
                    return (t.content);
                }}/>);
            });
        }
    }

    refreshOpenTab = (e) =>{
        // this approach works, forces a rerender of the component, which does not work in case of nested tabs, will revert to starting tab
        // still good to have for simple cases where we want to force refresh a tab withouth the internal component supporting it explicitly
        this.currentTab = this.state.openTab;
        if (this.props.beforeSwitch(e,
            (cb) => {
                this.setState({openTab: -1}, cb);
            }, -1, this.state.openTab)) {
            this.setState({openTab: -1});
        }
    };

    setTabFromId = (tabId) => {
        const newTab = _.findIndex(this.props.tabs, {key: tabId});
        if (newTab >= 0) {
            this.setState({openTab: newTab});
        }
    };

    componentDidMount() {
        if (typeof this.props.refreshTrigger === 'function') {
            this.props.refreshTrigger(this.refreshOpenTab);
        }
        // this lets external components switch tabs for non routed ones
        if (typeof this.props.setTab === 'function') {
            this.props.setTab(this.setTabFromId);
        }
    }

    componentDidUpdate() {
        if (this.state.openTab === -1) {
            // we were forcing a refresh
            // the rule is a good one, but in this case I know what I am doing
            // eslint-disable-next-line react/no-did-update-set-state
            this.setState({openTab: this.currentTab});
        } else if (typeof this.props.refreshTrigger === 'function') {
            this.props.refreshTrigger(this.refreshOpenTab);
        }
    }

    renderTab(t, i) {
        let selectTab = (e, pos) => {
            if (this.props.beforeSwitch(e, (cb) => {
                this.setState({openTab: pos}, cb);
            }, pos, this.state.openTab)) {
                this.setState({openTab: pos});
            }
        };
        let tabClasses = [CLASSES.MAIN];
        if (i === this.state.openTab) {
            tabClasses.push(CLASSES.ACTIVE);
        }

        return (
            <li key={`tab${i}`} className={tabClasses.join(' ')} onClick={(e) => {
                selectTab(e, i);
            }}>
                <a>
                    <div className={CLASSES.HEADING} title={t.title || t.label}>{t.label}</div>
                </a>
            </li>
        );
    }

    renderRoutedTab(t) {
        let selectTab = (e, to) => {
            if (!this.props.beforeSwitch(e, to)) {
                e.preventDefault();
            }
        };

        return (
            <Route key={`${t.key}`} path={`${this.props.basePath}/${t.key}`} children={({match}) => {
                let tabClasses = [CLASSES.MAIN];
                if (match) {
                    tabClasses.push(CLASSES.ACTIVE);
                }
                return (
                    <li className={tabClasses.join(' ')} onClick={(e) => {
                        selectTab(e, `${this.props.basePath}/${t.key}`);
                    }}>
                        <Link title={t.title || t.label} to={`${this.props.basePath}/${t.key}`}>
                            <div className={CLASSES.HEADING}>{t.label}</div>
                        </Link>
                    </li>
                );
            }}/>
        );
    }

    renderTabs() {
        let items;
        if (!this.props.live && this.props.basePath) {
            items = this.props.tabs.map(
                (t, i) => (this.renderRoutedTab(t, i))
            );
        } else {
            items = this.props.tabs.map(
                (t, i) => (this.renderTab(t, i))
            );
        }

        let classes = [CLASSES.TABS];
        if (this.props.vertical) {
            classes.push(CLASSES.TABS_VERTICAL);
        }

        return (
            <div className={this.props.type + ' tab-header'}>
                <ul className={classes.join(' ')}>
                    {items}
                </ul>
            </div>
        );
    }

    renderTabContent(tab) {
        if (tab.content) {
            return (<div className="tab-content">{tab.content}</div>);
        }
        return (
            <div className="tab-content">No content defined for tab {tab.label}</div>
        );
    }

    renderLiveTabsContent() {
        const {openTab} = this.state;
        let content = [];
        let tabsContent = this.tabsContent;
        this.props.tabs.forEach(function(t, i) {
            content.push(<div key={`${t.key}`} style={{display: i === openTab ? null : 'none'}}>{tabsContent[i]}</div>);
        });
        return content;
    }

    renderRouted(classes) {
        if (this.state.openTab === -1) {
            return (<Loader/>);
        }
        return (
            <div className={classes.join(' ')}>
                {this.renderTabs()}
                <Router>
                    <Switch>
                        {this.routes}
                        {this.baseRoute}
                    </Switch>
                </Router>
            </div>
        );
    }

    renderLive(classes) {
        return (
            <div className={classes.join(' ')}>
                {this.renderTabs()}
                {this.renderLiveTabsContent()}
            </div>
        );
    }

    render() {
        let classes = [CLASSES.EXTERNAL_CLASS_NAME];
        if (this.props.vertical) {
            classes.push(CLASSES.VERTICAL);
        }

        if (this.props.cmpStyle) {
            classes.push(this.props.cmpStyle);
        }

        if (this.props.live) {
            return this.renderLive(classes);
        }

        if (this.props.basePath) {
            return this.renderRouted(classes);
        }

        return (
            <div className={classes.join(' ')}>
                {this.renderTabs()}
                {this.state.openTab >= 0 ? this.renderTabContent(this.props.tabs[this.state.openTab]) : <Loader/>}
            </div>
        );
    }
}

Tabs.TYPE = {
    PRIMARY: 'primary-tabs',
    SECONDARY: 'secondary-tabs'
};

Tabs.propTypes = {
    basePath: PropTypes.string,
    type: PropTypes.oneOf(Object.values(Tabs.TYPE)),
    tabs: PropTypes.array.isRequired,
    vertical: PropTypes.bool,
    live: PropTypes.bool,
    beforeSwitch: PropTypes.func,
    refreshTrigger: PropTypes.func,
    setTab: PropTypes.func,
    cmpStyle: PropTypes.string
};

Tabs.defaultProps = {
    type: Tabs.TYPE.SECONDARY,
    live: false,
    beforeSwitch: () => {
        return true;
    }
};

export {Tabs};
