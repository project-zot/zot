import React from 'react';
import PropTypes from 'prop-types';
import {WidgetPanel} from '../widgets/panel/WidgetPanel';
import {PropertyListItem} from '../common/PropertyListItem';
import {StatusTile} from '../../pages/dashboard/StatusTile';
import LABELS from '../../strings';

class GeneralWidgetPanel extends React.Component {
    render() {
        const {obj, ...rest} = this.props;
        return (
            <WidgetPanel {...rest} title={LABELS.General} collapsible={true}>
                <ul className="list">
                    <PropertyListItem label={LABELS.status} value={obj.status || '-'} >
                        <StatusTile text={obj.status || '-'} showBorder/>
                    </PropertyListItem>
                    <PropertyListItem label={LABELS.nodeRole} value={obj.nodeRole || '-'} />
                    <PropertyListItem label={LABELS.serial} value={obj.serial || '-'} />
                    <PropertyListItem label={LABELS.inBand} value={obj.inbandIP || '-'} />
                    <PropertyListItem label={LABELS.inBandG} value={obj.inbandGW || '-'} />
                    <PropertyListItem label={LABELS.outBand} value={obj.oobIP || '-'} />
                    <PropertyListItem label={LABELS.outBandGateway} value={obj.oobGW || '-'} />

                </ul>
            </WidgetPanel>
        );
    }
}

GeneralWidgetPanel.defaultProps = {
};

GeneralWidgetPanel.propTypes = {
    obj: PropTypes.object
};

export {GeneralWidgetPanel};
