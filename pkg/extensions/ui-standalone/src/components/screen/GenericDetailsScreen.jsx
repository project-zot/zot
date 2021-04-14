import React from 'react';
import PropTypes from 'prop-types';
import {GenericDetailsScreenLoadingSkeleton} from '../../components/screen/GenericDetailsScreenLoadingSkeleton';
import {DetailsScreen} from '../../components/screen/DetailsScreen';
import {Tabs} from '../Tabs';
import LABELS from '../../strings';
import {SESSION} from '../../common/utils/session';
import api from '../../common/utils/api';

class GenericDetailsScreen extends React.Component {
    constructor(props) {
        super(props);
        this.state = {
            snData: [],
            loading: true
        };
    }

    componentDidMount() {
        this.fetchApi();
    }

    fetchApi() {
    }

    refresh = () => {
        this.fetchApi();
    };

    renderContent = () => {
        return <GenericDetailsScreenLoadingSkeleton />;
    };

    render() {
        return (
            <DetailsScreen
                {...this.props}
                moObj={this.state.snData}
                loading={this.state.loading}
                onRefresh={this.refresh}
                render={this.renderContent}
                content={this.content}
            />
        );
    }
}

GenericDetailsScreen.propTypes = {
    data: PropTypes.object
};

export {GenericDetailsScreen};
