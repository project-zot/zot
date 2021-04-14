// react global
import React, {Fragment} from 'react';
import PropTypes from 'prop-types';

// components
import {Card} from 'blueprint-react';
import {WidgetPanel} from '../../components/widgets/panel/WidgetPanel';
import {Tabs} from '../../components/Tabs';
import {PropertyListItem} from '../../components/common/PropertyListItem';
import {PlainTable} from '../../components/table/PlainTable';
import {SeFilterableTable} from '../../components/table/SeFilterableTable';
import {ImageTileLarge} from './ImageTileLarge';

// utility
import LABELS from '../../strings';
import {SITE_TYPE} from '../../constants';
import {SESSION} from '../../common/utils/session';
import {uiUtils} from '../../common/utils/ui-utils';
import {isEmpty} from 'lodash';

// styling
import '../../standalone/pages/sitedashboard/SiteSummary.scss';
import './ImageTile.scss';

class ImagesDetailContent extends React.Component {
    constructor(props) {
        super(props);
    }

    render() {
        const {obj, imageData, isLoading} = this.props;
        const {size, licenses} = obj;

        const cards = (
            <div className="top-wrapper">
                <div className="text-card">
                    <Card key="cisco-card-1" cardAlignment={Card.ALIGNMENT.DEFAULT} headerContent={LABELS.size}
                        bodyContent={size + ' bytes'}/>
                </div>
                <div className="text-card">
                    <Card key="cisco-card-2" cardAlignment={Card.ALIGNMENT.DEFAULT} headerContent={LABELS.lastUpdated}
                        bodyContent="6 hours ago"/>
                </div>
                <div className="text-card">
                    <Card key="cisco-card-3" cardAlignment={Card.ALIGNMENT.DEFAULT} headerContent={LABELS.license}
                        bodyContent={licenses || '-'}/>
                </div>
            </div>
        );

        const verCards = (
            <div className="top-wrapper">
                <div className="text-card">
                    <Card classes="tect-card-TEST" key="cisco-card-2" cardAlignment={Card.ALIGNMENT.DEFAULT} headerContent={LABELS.lastUpdated}
                        bodyContent="-"/>
                </div>
            </div>
        );

        const versions = imageData && imageData.tags;
        const dependencies = imageData && imageData.layers;

        const tabs = [
            {
                key: 'readme',
                label: LABELS.readme,
                content: (
                    <div>
                        <ul className="list">
                            <PropertyListItem label={LABELS.generalInformation}>
                                {cards}
                            </PropertyListItem>
                            <PropertyListItem label={LABELS.description} value={obj.description} />
                        </ul>
                    </div>
                )
            },
            {
                key: 'dependencies',
                label: LABELS.layers,
                content: (
                    <PlainTable
                        columns={[
                            {
                                accessor: 'size',
                                Header: 'Size',
                                Cell: (row) => (row.original.size + ' b'),
                            },
                            {
                                accessor: 'layerID',
                                Header: 'Digest'
                            },
                        ]}
                        data={dependencies}
                    />
                )
            },
            {
                key: 'tags',
                label: LABELS.tags,
                content: (
                    <div>
                        <div>
                            <ul className="list">
                                <PropertyListItem label={LABELS.currentTags}>
                                    <SeFilterableTable
                                        columns={[{
                                            Header: 'Tag',
                                            accessor: 'tagID',
                                        }]}
                                        data={versions}
                                        minRows={1}
                                        pageSize={5}
                                    />
                                </PropertyListItem>
                            </ul>
                        </div>
                    </div>
                )
            },
        ];

        return (

            <div className="col-sm-12">
                <div style={{marginTop: 10}}>
                    <ImageTileLarge
                        name={obj.name}
                        description={obj.description}
                        version={obj.version}
                        vendor={obj.vendor}
                        tags={obj.tags}
                    />
                </div>
                <div style={{marginTop: 20}}>
                    <WidgetPanel>
                        <div className={'bottom-wrapper'}>
                            <Tabs tabs={tabs} />
                        </div>
                    </WidgetPanel>
                </div>
            </div>

        );
    }
}

ImagesDetailContent.propTypes = {
    obj: PropTypes.any,
    isLoading: PropTypes.bool,
};

export {ImagesDetailContent};
