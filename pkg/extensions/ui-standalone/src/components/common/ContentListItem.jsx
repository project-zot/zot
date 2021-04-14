import React from 'react';
import PropTypes from 'prop-types';

const SPACE = ' ';
const CLASSES = {
    TITLE: 'card__title_summary_domain',
    SPACING: 'info_modal'
};

class ContentListItem extends React.Component {
    render() {
        const {title = '', content = '', className = 'col-sm-4'} = this.props;
        let classes = [CLASSES.SPACING];

        if (className) {
            classes.push(className);
        }

        return (
            <div className={classes.join(SPACE)} style={{paddingLeft: '0px'}}>
                <div className={CLASSES.TITLE}>{title}</div>
                <div>{content}</div>
            </div>
        );
    }
}

ContentListItem.propTypes = {
    className: PropTypes.string,
    title: PropTypes.string,
    content: PropTypes.string,
};

export {ContentListItem};
