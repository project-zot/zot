// react global
import React, {Fragment} from 'react';
import PropTypes from 'prop-types';

// components
import {ImageTileLarge} from '../screens/details/ImageTileLarge';

// utility
import {isEmpty} from 'lodash';
import LABELS from '../strings';

// styling
import './AppsTile.scss';

class AppsTile extends React.Component {
    constructor(props) {
        super(props);
    }

    renderFailedCmp = (item) => {
        return (
            <div className="failed-cmp">
                <div><span className="icon-error-outline icon-large health_critical" /></div>
                <div className="failed-title">{LABELS.installationFailed}</div>
            </div>
        );
    }

    renderAppsCmp = () => {
        const {data, searchValue} = this.props;
        const filterStr = searchValue.toLocaleLowerCase();

        const cmp = data && data.map((item, index) => {
            return (
                <ImageTileLarge
                    name={item.name}
                    version={item.latestVersion}
                    description={item.description}
                    tags={item.tags}
                    vendor={item.vendor}
                    size={item.size}
                    licenses={item.licenses}
                    key={index}
                    compressed
                />
            );
            // TODO: use this instead
            // return (
            //     <ImageTileLarge
            //         {...this.props}
            //         name={item.name}
            //         version={item.latestVersion}
            //         description={item.description}
            //         tags={item.tags}
            //         key={item.id}
            //         data={item}
            //         shown={isEmpty(searchValue) ||
            //             item.displayName.toLocaleLowerCase().indexOf(filterStr) >= 0 ||
            //             (item.appID && item.appID.toLocaleLowerCase().indexOf(filterStr) >= 0) ||
            //             (item.appId && item.appId.toLocaleLowerCase().indexOf(filterStr) >= 0)}
            //     />
            // );
        });
        return cmp;
    }

    render() {
        return (
            <Fragment>
                <div className="images-tiles-container">
                    {this.renderAppsCmp()}
                </div>
            </Fragment>
        );
    }
}

AppsTile.propTypes = {
    data: PropTypes.array,
    openSummaryPane: PropTypes.func,
    openModal: PropTypes.func,
    searchValue: PropTypes.string,
};

export {AppsTile};
