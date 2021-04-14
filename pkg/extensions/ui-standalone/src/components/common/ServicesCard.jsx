import React from 'react';
import PropTypes from 'prop-types';
import _ from 'lodash';
import {Card, CardHeader, CardBody, CardFooter, Label, Link} from 'blueprint-react';
import {EmptyCard} from '../utils/EmptyCard';
import appssetup from '../../../public/icons/appssetup.svg';
import {uiUtils} from '../../common/utils/ui-utils';
import {URL, AUTH_STATUS} from '../../constants';
import LABELS from '../../strings';

import './ServicesCard.scss';

class ServicesCard extends React.Component {
    constructor(props) {
        super(props);
        this.state = {
            hoveredCard: null,
            message: '',
            iconAvailable: true,
        };
    }

    _getObjectId = (obj) => {
        const {uidAccessor} = this.props;
        if (_.isFunction(uidAccessor)) {
            return obj[uidAccessor(obj)]; // per object.  use when you need to construct a unique id for the object.
        }
        return _.get(obj, uidAccessor); // simple string that can be a dot delimited path to a unique identifier.
    };

    handleOnCardHovered = (uid, event) => {
        this.setState({
            hoveredCard: uid,
        });
    };

    handleOnCardUnHovered = (uid, event) => {
        this.setState({
            hoveredCard: null,
        });
    };

    renderIcon = (id) => {
        const {iconAvailable} = this.state;
        let iconCmp;
        let url = `${window.location.origin}${URL.applicationList}/${id}/icon`;
        // Icon will not be available when app is Installing -> Dont show ICON image.
        if (iconAvailable) {
            iconCmp = (
                <img
                    className="tile-icon"
                    src={url}
                    onError={() => {
                        this.setState({iconAvailable: false});
                    }}
                />
            );
        } else if (!iconAvailable) {
            iconCmp = (
                <div className="apps-dot-label">
                    {' '}
                    <span>{LABELS.appText}</span>
                </div>
            );
        }
        return iconCmp;
    };

    carlistCmp = () => {
        const {siteData, userRbac, appData} = this.props;
        let cardList;

        // Get total number app's configured to sites
        const newObj = siteData.reduce((appObj, obj) => {
            obj.apps.forEach((app) => {
                let aName = app.appName.toLowerCase();
                if (app.vendor) {
                    aName = `${app.vendor}_${app.appName}`;
                }
                if (appObj[aName]) {
                    appObj[aName].push(obj);
                } else {
                    appObj[aName] = [obj];
                }
            });

            return appObj;
        }, {});

        // Sort the application which are installed and running.
        appData.sort((a, b) => a.name > b.name ? 1 : -1);
        cardList = appData.map((cardItem, index) => {
            let uid = this._getObjectId(cardItem);
            let detailIcon = '';
            let cls = ['service-footer-txt'];
            let footerTxt = LABELS.troubleshooting;
            if (cardItem.displayName === 'Multi-Site Orchestrator') {
                cls.push('service-others');
                footerTxt = LABELS.orchestration;
            }

            if (userRbac !== AUTH_STATUS.DASHBOARD_USER) {
                detailIcon = (
                    <div style={{float: 'right', paddingRight: '15px'}}>
                        {this.state.hoveredCard === uid && (
                            <span
                                style={{position: 'absolute'}}
                                className="link icon-jump-out icon-small"
                                onClick={(e) => {
                                    e.stopPropagation();
                                    this.props.openDetailsScreen('app', '', cardItem);
                                }}
                            />
                        )}
                    </div>
                );
            }

            if (!_.isEmpty(cardItem)) {
                const obj = newObj[cardItem.name.replace('-', '_')] || [];
                return (
                    <div
                        style={{cursor: 'pointer'}}
                        className="col-md-4 pb"
                        onClick={(e) => {
                            e.stopPropagation();
                            const appLaunchUrl = uiUtils.getAppLaunchUrl(cardItem);
                            window.open(appLaunchUrl);
                        }}
                    >
                        <Card
                            key={uid}
                            uid={uid}
                            raised={true}
                            hoverable={true}
                            onHovered={(e) => {
                                this.handleOnCardHovered(uid, e);
                            }}
                            onUnHovered={(e) => {
                                this.handleOnCardUnHovered(uid, e);
                            }}
                        >
                            {detailIcon}
                            <CardHeader>
                                <div className="image-container">{this.renderIcon(cardItem.id)}</div>
                                <div style={{position: 'absolute', paddingLeft: '100px'}}>
                                    <div key={'cc-div-'.concat(uid)} className="card__title">
                                        {cardItem.displayName}
                                    </div>
                                    <div key={'cc-div-'.concat(uid + 1)} className="card__subtitle">
                                        {cardItem.version}
                                    </div>
                                </div>
                            </CardHeader>
                            <CardBody style={{textAlign: 'center'}}>
                                {
                                    <div style={{paddingTop: '5px'}}>
                                        <Link
                                            style={{
                                                fontSize: '30px',
                                                fontWeight: '30px',
                                            }}
                                            onClick={(e) => {
                                                e.stopPropagation();
                                                if (obj.length > 0) {
                                                    this.props.openObjectsListPane({type: 'site', objectsList: obj, paneTitle: LABELS.site, jumpOutIcon: userRbac !== AUTH_STATUS.DASHBOARD_USER ? true : false});
                                                }
                                            }}
                                        >
                                            {obj.length}
                                        </Link>
                                        <div>{LABELS.sites}</div>
                                    </div>
                                }
                            </CardBody>
                            <CardFooter>
                                <span className={cls.join(' ')}>{footerTxt}</span>
                            </CardFooter>
                        </Card>
                    </div>
                );
            }
        });
        return cardList;
    };

    render() {
        const {userRbac, appData} = this.props;
        let cmp;
        if (!_.isEmpty(appData)) {
            cmp = this.carlistCmp();
        } else {
            // EmptyCard Check for Dashboard user and Admin user
            cmp = (
                <div style={{width: '100%'}}>
                    <EmptyCard
                        imgSrc={appssetup}
                        title={LABELS.noServices}
                        desc={userRbac !== AUTH_STATUS.DASHBOARD_USER ? LABELS.dontHaveServices : LABELS.duNoServicesTxt}
                    />
                </div>
            );
        }

        return (
            <div className="row" key="cards-key-id" headerContent="Your Services">
                {cmp}
            </div>
        );
    }
}

ServicesCard.propTypes = {
    siteData: PropTypes.array,
    appData: PropTypes.array,
    openDetailsScreen: PropTypes.func,
    openObjectsListPane: PropTypes.func,
    data: PropTypes.arrayOf(PropTypes.shape({})),
    uidAccessor: PropTypes.oneOfType([PropTypes.string, PropTypes.func]),
    userRbac: PropTypes.string,
};

ServicesCard.defaultProps = {
    uidAccessor: 'id',
};

export {ServicesCard};
