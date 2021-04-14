import _ from 'lodash';
import React from 'react';
import PropTypes from 'prop-types';

import {GenericDetailsScreen} from './GenericDetailsScreen';

class ScreensRenderer extends React.Component {
    render() {
        const length = this.props.openedScreens.length;
        return (
            this.props.openedScreens.map((screenData, i) => {
                let screenProps = {
                    id: screenData.key,
                    onClose: this.props.onClose,
                    onMinimize: this.props.onMinimize,
                    saveTitle: this.props.saveTitle,
                    data: screenData,
                    obj: screenData.obj,
                    toBeClosed: screenData.toBeClosed,
                    minimized: screenData.minimized,
                    active: i === length - 1
                };
                // active: i === length - 1 this will mark the last screen in the list as the current active
                let ScreenComponent = this.props.screenComponents[screenData.type];
                if (screenData.type.startsWith(this.props.detailsPrefix)) {
                    // use the generic details screen if a specific one is not specified
                    ScreenComponent = _.get(this.props.screenComponents, screenData.type, GenericDetailsScreen);
                }
                return <ScreenComponent key={screenData.key} {...screenProps}/>;
            })
        );
    }
}

ScreensRenderer.propTypes = {
    openedScreens: PropTypes.array.isRequired,
    screenComponents: PropTypes.object,
    detailsPrefix: PropTypes.string,
    onClose: PropTypes.func,
    onMinimize: PropTypes.func,
    saveTitle: PropTypes.func
};

ScreensRenderer.defaultProps = {
    openedScreens: []
};

export {ScreensRenderer};
