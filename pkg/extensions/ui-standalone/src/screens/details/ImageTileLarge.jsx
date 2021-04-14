// react global
import React from 'react';
import PropTypes from 'prop-types';
import {connect} from 'react-redux';

// components
import {WidgetPanel} from '../../components/widgets/panel/WidgetPanel';

// utility
import {setupActions} from '../../state/setup/action';
import {appActions} from '../../state/app/action';

import LABELS from '../../strings';
import {SITE_TYPE} from '../../constants';
import {SESSION} from '../../common/utils/session';
import {uiUtils} from '../../common/utils/ui-utils';
import {isEmpty} from 'lodash';

// styling
import '../../standalone/pages/sitedashboard/SiteSummary.scss';
import './ImageTile.scss';

class ImageTileLarge extends React.Component {
    constructor(props) {
        super(props);
        this.state = {
            error: {},
        };
    }
    //
    // componentDidMount() {
    //     this.fetchApi();
    //     this.timer = setInterval(() => {
    //         this.fetchApi();
    //     }, 10000);
    // }
    //
    // componentWillUnmount() {
    //     clearInterval(this.timer);
    // }
    //
    // fetchApi = () => {
    //     const {
    //         data: {name, operState},
    //     } = this.props;
    //     const {appsData} = this.state;
    //     if (operState === 'Running') {
    //         Promise.all([api.get(URL.pods + '/' + name), api.get(URL.container + '/' + name), api.get(URL.getActiveResourceProfile + name)])
    //             .then((response) => {
    //                 const [podsData, containerData, appInstanceData] = response;
    //                 const {instances} = appInstanceData.data;
    //                 let appInstance, uiEntrypoint = '';
    //                 if (!isEmpty(instances)) {
    //                     appInstance = instances[0].operState;
    //                     uiEntrypoint = instances[0].uiEntrypoint;
    //                 }
    //                 const data = {
    //                     usedPods: podsData.data.status.running,
    //                     totalPods: podsData.data.listMeta.totalItems,
    //                     usedContainers: containerData.data.status.running,
    //                     totalContainers: containerData.data.listMeta.totalItems,
    //                     appInstance,
    //                     uiEntrypoint
    //                 };
    //                 this.setState({appsData: data, isLoading: false});
    //             })
    //             .catch(() => {
    //                 this.setState({appsData, isLoading: false});
    //             });
    //     } else {
    //         this.setState({appsData, isLoading: false});
    //     }
    // };

    // TODO :: naman
    tileClick = (e) => {
        const {name, version, description, tags, vendor, size, licenses} = this.props;
        const obj = {
            name: name,
            version: version,
            description: description,
            tags: tags,
            vendor: vendor,
            size: size,
            licenses: licenses
        };
        this.props.openDetailsScreen('image', name, obj);
        e.stopPropagation();
    }

    renderIcon = () => {
        const {compressed} = this.props;
        let iconCls = compressed ? 'image-icon-extra-small' : 'image-icon-small';

        return (
            <div className={iconCls}>
                {' '}
                <span>{LABELS.appLogo}</span>
            </div>
        );
    };

    render() {
        const {className, data, name, version, description, vendor, size, tags, shown = true, compressed} = this.props;
        const {error} = this.state;
        let vendorID = vendor || '-';
        let desc =  description || '-';

        // TODO: fix this
        let bodyStyle = '', style = {};
        if (!shown) {
            style = {display: 'none'};
        }

        let imgTags = !isEmpty(tags) ? tags.split(',') : [];
        let imageTags = !isEmpty(imgTags) && imgTags.map((tag) => {
            return (
                <div className={'tag'}>{uiUtils.getImageTag(tag)}</div>
            );
        });

        // add specific classes for 'compressed' flavor
        let imageDetailsClasses = 'image-details-container';
        if (compressed) {
            imageDetailsClasses = imageDetailsClasses + '-compressed';
        }

        return (
            <div onClick={(e) => this.tileClick(e)}>
                <WidgetPanel>
                    {
                        // use below for conditional rendering
                    }
                    <div className={`top-wrapper ${bodyStyle}`}>
                        <div>{this.renderIcon()}</div>
                        <div className={imageDetailsClasses}>
                            <div className={'name'}>{name}</div>
                            {compressed ?
                                (
                                    <div>
                                        <div className={'version'}>{version}</div>
                                        <div className={'description'}>{desc}</div>
                                        <div className={'tags'}>{imageTags}</div>
                                    </div>
                                ) :
                                (
                                    <div>
                                        <div className={'version'}>Version: {version}</div>
                                        <div className={'vendor'}>Vendor: {vendorID}</div>
                                        <div className={'tags'}>{imageTags}</div>
                                    </div>
                                )
                            }
                        </div>
                    </div>
                </WidgetPanel>
            </div>
        );
    }
}

ImageTileLarge.defaultProps = {
    className: 'apps-tile-container',
};

ImageTileLarge.propTypes = {
    shown: PropTypes.bool,
    title: PropTypes.any,
    className: PropTypes.string,
    data: PropTypes.object,
    onClick: PropTypes.func,
    openModal: PropTypes.func,
    onRefresh: PropTypes.func,
    errorMessageCallBack: PropTypes.func,
    openSummaryPane: PropTypes.func
};

const mapDispatchToProps = (dispatch) => ({
    ...setupActions(dispatch),
    ...appActions.merge([appActions.SCREEN_ACTIONS, appActions.SUMMARY_PANE_ACTIONS, appActions.MODAL_ACTIONS])(dispatch),
});

ImageTileLarge = connect(null, mapDispatchToProps)(ImageTileLarge);

export {ImageTileLarge};
