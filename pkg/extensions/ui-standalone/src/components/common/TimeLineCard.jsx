import React from 'react';
import PropTypes from 'prop-types';
import {isEmpty} from 'lodash';
import onClickOutside from 'react-onclickoutside';
import {TitledTooltip, Popup, CollapsiblePanel} from 'blueprint-react';

import {uiUtils} from '../../common/utils/ui-utils';
import {STATUS_TYPE_MAP} from '../../constants';

import './TimeLineCard.scss';

class TimeLineCard extends React.Component {
    constructor(props) {
        super(props);
        this.state = {
            isActive: false,
        };
    }

    handleClick = (event) => {
        if (!this.state.isActive) {
            event.stopPropagation();
            this.setState({isActive: !this.state.isActive});
        }
    }

    renderTimeLinecmp = () => {
        const {data, accessor, sortByTime} = this.props;
        const items = [];
        const timeKey = accessor && accessor.time || 'time';
        const nameKey = accessor && accessor.name || 'name';
        const statusKey = accessor && accessor.status || 'status';
        const durationKey = accessor && accessor.duration || 'duration';
        let classes = ['timeline-card'];
        let contentClasses = ['timeline-card-content'];
        let content, dataCopy;

        if (!isEmpty(data) && data.length) {
            dataCopy = [...data];
            if (sortByTime) {
                dataCopy.sort((item1, item2) => item1[timeKey] > item2[timeKey] ? -1 : 1);
            }
            dataCopy.forEach((item, index) => {
                let iconClasses = ['timeline-card-icon'];
                let status = item[statusKey] && item[statusKey].toLowerCase();
                let detail = item.steps && item.steps.length && item.steps.map((step, stepIdx) => {
                    const stepStatus = step.returnStatus || step.status;
                    let stepIconClasses = ['sub-timeline-icon'];
                    if (stepStatus && STATUS_TYPE_MAP[stepStatus]) {
                        stepIconClasses.push(stepStatus && STATUS_TYPE_MAP[stepStatus] || STATUS_TYPE_MAP.UNKNOWN);
                    }
                    return (
                        <div key={'sub-timeline-item-' + index + '-' + stepIdx} className="sub-timeline-item">
                            <div className={stepIconClasses.join(' ')}><span className="" /></div>
                            <div className="sub-timeline-content">
                                <div>{step.name}</div>
                                <div>{step.status}</div>
                            </div>
                        </div>);
                }) || '';

                iconClasses.push(STATUS_TYPE_MAP[status] || STATUS_TYPE_MAP.UNKNOWN);
                content = (item[nameKey] ? item[nameKey] + ': ' : '') + item[statusKey] + (item[durationKey] ? ' [' + item[durationKey] + ']' : '');
                if (detail) {
                    contentClasses.push('content-with-detail');
                    content = (<CollapsiblePanel title={content} collapsed={index !== 0}>
                        <div className="sub-timeline">{detail}</div>
                    </CollapsiblePanel>);
                } else {
                    content = <div>{content}</div>;
                }

                items.push(
                    <div key={'timeline-item-' + index} className="timeline-card-item">
                        <div className="timeline-card-title">{uiUtils.getTimeString(item[timeKey]) || '' }</div>
                        <div className={iconClasses.join(' ')}>
                            <span className="" />
                        </div>
                        <div className={contentClasses.join(' ')}>
                            {content}
                        </div>
                    </div>
                );
            });
        }

        if (items && items.length) {
            return (<div className={classes.join(' ')}> <div className="timeline" >{items}</div></div>);
        }
        return;
    }

    render() {
        const {children} = this.props;
        const {isActive} = this.state;
        let opened = false;
        let timelineCmp = this.renderTimeLinecmp();

        if (isActive && timelineCmp) {
            opened = true;
        }

        return (
            <div className="TimeLineCard" onClick={this.handleClick}>
                <TitledTooltip
                    triggerEvent={Popup.TRIGGER.CLICK}
                    title={''}
                    // position={TitledTooltip.POSITION.LEFT_START}
                    controlled={true}
                    opened={opened}
                    content={timelineCmp}
                >
                    <div>{children}</div>
                </TitledTooltip>
            </div>
        );
    }

    handleClickOutside = () => {
        if (this.state.isActive) {
            this.setState({isActive: false});
        }
    };
}

TimeLineCard.propTypes = {
    children: PropTypes.object,
    data: PropTypes.any,
    accessor: PropTypes.object,
    sortByTime: PropTypes.bool
};
TimeLineCard = (onClickOutside(TimeLineCard));

export {TimeLineCard};
