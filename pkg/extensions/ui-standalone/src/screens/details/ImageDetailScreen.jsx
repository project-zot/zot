import React from 'react';
import PropTypes from 'prop-types';
import {isEmpty} from 'lodash';
import {connect} from 'react-redux';

import {appActions} from '../../state/app/action';

import {Tabs} from '../../components/Tabs';
import {GenericDetailsScreenLoadingSkeleton} from '../../components/screen/GenericDetailsScreenLoadingSkeleton';
import {DetailsScreen} from '../../components/screen/DetailsScreen';
import {ImagesDetailContent} from './ImagesDetailContent';
import {EDIT_SCREEN_PREFIX} from '../../config/screens-config';
import {uiUtils} from '../../common/utils/ui-utils';
import {SESSION} from '../../common/utils/session';

import api from '../../common/utils/api';
import {URL, AUTH_STATUS} from '../../constants';
import LABELS from '../../strings';

class ImageDetailScreen extends React.Component {
    constructor(props) {
        super(props);
        this.state = {
            isLoading: true,
            imageData: [],
        };
    }

    componentDidMount() {
        this.getImageDetails();
    }

    getImageDetails = () => {
        const {obj} = this.props;
        const {name, version} = obj;

        const listOfTagsUrl = '/v2/' + name + '/tags/list';
        const listOfLayersUrl = '/v2/' + name + '/manifests/' + version;

        // TODO: add layers call
        Promise.all([api.get(listOfTagsUrl), api.get(listOfLayersUrl)])
            .then((response) => {
                const {tags} = response[0] && response[0].data;

                let tagsData = tags.map((tag) => {
                    return {
                        tagID: tag,
                    };
                });

                const {layers} = response[1] && response[1].data;
                let layersData = layers.map((layer) => {
                    return {
                        name: '-',
                        layerID: layer.digest,
                        size: layer.size
                    };
                });

                this.setState({imageData: {tags: tagsData, layers: layersData}});
            })
            .catch(() => {
                this.setState({imageData: {tags: [], layers: []}});
            });
    };

    refresh = () => {
        // const {
        //     data: {obj},
        // } = this.props;
        // obj.successCallBack();
        // this.getSiteUser();
    };

    renderContent = () => {
        if (this.state.loading) {
            return <GenericDetailsScreenLoadingSkeleton />;
        }
    };

    render() {
        const {data: {obj}} = this.props;
        // TODO: add tags and layers in data
        const {imageData, isLoading} = this.state;

        return (
            <DetailsScreen
                {...this.props}
                title={obj.name}
                moObj={imageData}
                loading={false}
                onRefresh={this.refresh}
                render={this.renderContent}
                content={<ImagesDetailContent obj={obj} isLoading={isLoading} imageData={imageData}/>}
            />
        );
    }
}

ImageDetailScreen.propTypes = {
    data: PropTypes.object,
    openModal: PropTypes.func,
    obj: PropTypes.any,
    openEditScreen: PropTypes.func,
    session: PropTypes.object
};

const mapStateToProps = (state) => ({
    session: state.session,
});

const mapDispatchToProps = (dispatch) => ({
    ...appActions.merge([appActions.SCREEN_ACTIONS])(dispatch),
});

ImageDetailScreen = connect(mapStateToProps, mapDispatchToProps)(ImageDetailScreen);

export {ImageDetailScreen};
