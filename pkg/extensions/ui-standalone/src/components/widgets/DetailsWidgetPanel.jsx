import React from 'react';
import PropTypes from 'prop-types';

import {WidgetPanel} from '../widgets/panel/WidgetPanel';
import {PropertyListItem} from '../common/PropertyListItem';

import LABELS from '../../strings';

class DetailsWidgetPanel extends React.Component {
    render() {
        const {obj: {status = '-', operState = '-'}, collapsible, ulClassName, itemClassName, ...rest} = this.props;

        return (
            <WidgetPanel {...rest} title={LABELS.settings} collapsible={collapsible}>
                <ul className={'list ' + ulClassName}>
                    <PropertyListItem className="col-sm-6" label={LABELS.operState} value={status} />
                    <PropertyListItem className="col-sm-6" label={LABELS.firmware} value={operState.version} />
                    <PropertyListItem className="col-sm-6" label={LABELS.upTime} value={'-'} />
                </ul>
            </WidgetPanel>
        );
    }
}

DetailsWidgetPanel.defaultProps = {
    collapsible: true,
    ulClassName: '',
    itemClassName: 'col-sm-6'
};

DetailsWidgetPanel.propTypes = {
    obj: PropTypes.object,
    collapsible: PropTypes.bool,
    ulClassName: PropTypes.string,
    itemClassName: PropTypes.string
};

export {DetailsWidgetPanel};
