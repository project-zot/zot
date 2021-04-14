import React from 'react';
import PropTypes from 'prop-types';

import LABELS from '../../strings';

const NBSP = '\u00A0';

class SummaryPaneHeader extends React.Component {
    constructor(props) {
        super(props);
    }

    render() {
        const {title = LABELS.userID, severity, status, icon} = this.props;
        let name = NBSP;
        let statusCmp;

        if (this.props.name) {
            name = this.props.name;
        }

        if (severity || status) {
            statusCmp = (
                <div className="item-health" />
            );
        } else if (icon) {
            statusCmp = (
                <div className="item-health">
                    {icon}
                </div>
            );
        } else {
            statusCmp = '';
        }

        return (
            <header>
                <div className="title-area">
                    {statusCmp}
                    <div className="item-info">
                        <div className="item-class">
                            {title}
                        </div>
                        <div className="item-name">
                            {name}
                        </div>
                    </div>

                </div>
            </header>
        );
    }
}

SummaryPaneHeader.defaultProps = {
    showParentsChain: false,
    skipHealth: false,
};

SummaryPaneHeader.propTypes = {
    title: PropTypes.string,
    obj: PropTypes.object,
    name: PropTypes.string,
    severity: PropTypes.string,
    status: PropTypes.string,
    icon: PropTypes.node
};

export {SummaryPaneHeader};
