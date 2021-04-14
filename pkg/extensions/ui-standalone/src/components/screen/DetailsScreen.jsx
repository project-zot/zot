import React from 'react';
import PropTypes from 'prop-types';
import {IconButton, Dropdown, Button} from 'blueprint-react';
import {Screen} from './Screen';
import {Tabs} from '../Tabs';
import LABELS from '../../strings';
import {SCREEN_TYPES, EDIT_SCREEN_PREFIX, CREATE_SCREEN_PREFIX as CP} from '../../config/screens-config';
import _ from 'lodash';
import {connect} from 'react-redux';
import {appActions} from '../../state/app/action';
import {FormError} from '../../components/form';
import './DetailsScreen.scss';

const LOADING_TAB_TITLE = '----------';

class DetailsScreen extends React.Component {
    constructor(props) {
        super(props);

        this.baseActionsMenuItems = [
            // {
            //     action: () => window.open('/visore.html#dn=' + this.props.moObj.dn, 'Store'),
            //     label: LABELS.openObjectStoreBrowser
            // }
        ];

        if (props.allowTags) {
            this.baseActionsMenuItems.push({
                action: () => {
                },
                label: LABELS.Tag
            });
        }

        this.actionsMenuItems = props.actionsMenuItems.concat(this.baseActionsMenuItems);
    }

    componentDidUpdate(prevProps) {
        // actionMenuItems can change on the fly
        if (this.props.actionsMenuItems !== prevProps.actionsMenuItems) {
            this.actionsMenuItems = this.props.actionsMenuItems.concat(this.baseActionsMenuItems);
            this.forceUpdate();
        }

        if (this.props.moObj && this.props.moObj !== prevProps.moObj) {
            const className = _.get(this.props, 'moObj._class', '');
            const isDeletable = _.get(this.props, 'allowDelete', SCREEN_TYPES[CP + className]);
            if (isDeletable) {
                this.actionsMenuItems.push({
                    action: () => {
                        this.props.openModal({type: 'DeleteModal', obj: this.props.moObj, moClass: this.props.moObj._class, successCallback: this.props.closeScreen});
                    },
                    title: LABELS.delete
                });
            }
        }
    }

    onEditSaveComplete = () => {
        this.props.onRefresh();
    };

    renderContent = () => {
        if (this.props.content) {
            return this.props.content;
        }
        if (this.props.render) {
            return this.props.render();
        }
        return 'No content defined';
    };

    renderContentSkeleton = () => {
        // const tabs = [
        //     {
        //         key: '1',
        //         label: LOADING_TAB_TITLE,
        //         content: <GenericDetailsScreenLoadingSkeleton showLoader={false}/>
        //     }
        // ];
        // return <Tabs tabs={tabs}/>;
    };

    render() {
        const {moObj, title = '', formError} = this.props;
        if (!moObj || moObj.length === 0) {
            return (
                <Screen className="details loading" title="Loading..." loading={true} hideFooter={true} {...this.props} allowMinimize={false}>
                    {this.renderContentSkeleton()}
                </Screen>
            );
        }

        return (
            <Screen className="details" {...this.props} title={title} hideFooter={true}>
                {this.renderContent()}
                <FormError error={formError} />
            </Screen>

        );
    }
}

DetailsScreen.defaultProps = {
    actionsMenuItems: [],
    allowTags: false,
};

DetailsScreen.propTypes = {
    moObj: PropTypes.any,
    openModal: PropTypes.func,
    closeScreen: PropTypes.func,
    onRefresh: PropTypes.func,
    skipEdit: PropTypes.bool,
    openEditScreen: PropTypes.func,
    menuItems: PropTypes.array,
    content: PropTypes.node,
    render: PropTypes.func,
    title: PropTypes.string,
    allowTags: PropTypes.bool,
    actionsMenuItems: PropTypes.array,
    onEdit: PropTypes.func,
    formError: PropTypes.obj
};

DetailsScreen = connect(() => ({}), appActions.merge([appActions.SCREEN_ACTIONS, appActions.MODAL_ACTIONS, appActions.GLOBAL_EVENTS_ACTIONS]))(DetailsScreen);
export {DetailsScreen};
