// react global
import React, {Fragment} from 'react';
import PropTypes from 'prop-types';
import {connect} from 'react-redux';

// components
import {Button, Dropdown, Link, TitledTooltip, Input} from 'blueprint-react';
import {SeFilterableTable} from '../../../components/table/SeFilterableTable';
import {FormError} from '../../../components/form/FormError';
import {AppPage} from '../../../components/AppPage';
import {AppsTile} from '../../../components/AppsTile';

// utility
import api from '../../../common/utils/api';
import {uiUtils} from '../../../common/utils/ui-utils';
import {URL} from '../../../constants';
import LABELS from '../../../strings';
import {isEmpty} from 'lodash';

// style
import '../sitedashboard/SiteSummary.scss';
import '../../../screens/details/ImageTile.scss';

class Images extends React.Component {
    constructor(props) {
        super(props);
        this.state = {
            data: [],
            formError: {},
            isLoading: false,
            searchValue: ''
        };

        this.columns = [
            {
                Header: LABELS.name,
                accessor: 'name',
            },
            {
                Header: LABELS.latestVersion,
                accessor: 'latestVersion',
            },
            {
                Header: LABELS.tags,
                accessor: 'tags',
                Cell: (row) => {
                    const {tags} = row.original;
                    let imageTags = tags && tags.map((tag) => {
                        return uiUtils.getImageTag(tag);
                    });
                    return <div>{imageTags || '-'}</div>;
                },
            },
        ];
    }

    componentDidMount() {
        this.getImagesApi();
    }

    onRefresh = () => {
        this.setState({formError: {code: '', text: ''}});
        this.getImagesApi();
    };

    onSearch = (event) => {
        this.setState({
            searchValue: event.target.value
        });
    };

    getImagesApi = () => {
        api.get(URL.imageList)
            .then((response) => {
                if (response.data && response.data.data) {
                    let imageList = response.data.data.ImageListWithLatestTag;
                    let imagesData = imageList.map((image) => {
                        return {
                            name: image.Name,
                            latestVersion: image.Latest,
                            tags: image.Labels,
                            description: image.Description,
                            licenses: image.Licenses,
                            size: image.Size,
                            vendor: image.Vendor
                        };
                    });
                    this.setState({data: imagesData, isLoading: false});
                }
            })
            .catch((error) => {
                let errorText = uiUtils.getErrorMessage(error);
                this.setState({data: [], isLoading: false, formError: {code: LABELS.error, text: errorText}});
            });
    };

    render() {
        const {...rest} = this.props;
        const {data, formError, isLoading, searchValue} = this.state;

        return (

            <div className="main-content-container">
                <AppPage title={LABELS.Images} onRefresh={this.onRefresh}>
                    <div className="search-container">
                        <Input type={Input.TYPE.SEARCH} size={Input.SIZE.COMPRESSED} value={searchValue} onChange={this.onSearch} />
                    </div>
                    <Fragment>
                        <AppsTile searchValue={searchValue} data={data} {...this.props} />
                    </Fragment>
                </AppPage>
            </div>
        );
    }
}

Images.propTypes = {
    onRefresh: PropTypes.any,
    openScreen: PropTypes.func,
    openModal: PropTypes.func,
};

export {Images};
