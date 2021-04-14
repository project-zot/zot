import React from 'react';
import PropTypes from 'prop-types';
import {SkeletonWidgetPanel} from '../widgets/skeleton/SkeletonWidgetPanel';
import {LoaderOverlay} from 'blueprint-react';

class GenericDetailsScreenLoadingSkeleton extends React.Component {
    render() {
        return (
            <main className="row details-skeleton" style={{flexDirection: 'row'}}>
                {this.props.showLoader ? <LoaderOverlay/> : null}
                <div className="col-sm-3">
                    <SkeletonWidgetPanel/>
                    <SkeletonWidgetPanel/>
                </div>
                <div className="col-sm-6">
                    <SkeletonWidgetPanel properties="9" twoColumns={true}/>
                </div>
                <div className="col-sm-3">
                    <SkeletonWidgetPanel/>
                    <SkeletonWidgetPanel/>
                    <SkeletonWidgetPanel/>
                </div>
            </main>
        );
    }
}

GenericDetailsScreenLoadingSkeleton.defaultProps = {
    showLoader: true
};

GenericDetailsScreenLoadingSkeleton.propTypes = {
    showLoader: PropTypes.bool
};

export {GenericDetailsScreenLoadingSkeleton};
