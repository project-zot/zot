import React from 'react';
import LABELS from '../strings';
import PropTypes from 'prop-types';
import './FieldTooltip.scss';

const POSITION = {
    UP: 'up',
    UP_LEFT: 'up-left',
    UP_RIGHT: 'up-right',
    DOWN: 'down',
    DOWN_LEFT: 'down-left',
    DOWN_RIGHT: 'down-right',
    LEFT: 'left',
    RIGHT: 'right'
};
const SIZE = {
    SMALL: 'small',
    MEDIUM: 'medium',
    LARGE: 'large',
    XLARGE: 'xlarge',
    FIT: 'fit'
};

class FieldTooltip extends React.Component {
    render() {
        let {title, content = false, position, size} = this.props;
        title = title.replace(/\*$/, '');
        if (content !== false) {
            return (
                <div className="field-tooltip-icon icon-info-circle">
                    {/* using valueOf allows the control characters to display correctly in the browser*/}
                    <div className="field-tooltip"
                        tabIndex="0"
                        data-balloon={content.valueOf()}
                        data-balloon-title={title}
                        data-balloon-pos={position}
                        data-balloon-length={size}
                    />
                </div>
            );
        }
        return null;
    }
}

FieldTooltip.propTypes = {
    title: PropTypes.string,
    position: PropTypes.oneOf(Object.values(POSITION)),
    size: PropTypes.oneOf(Object.values(SIZE))
};

FieldTooltip.defaultProps = {
    title: LABELS.help,
    position: POSITION.RIGHT,
    size: SIZE.LARGE
};

FieldTooltip.POSITION = POSITION;
FieldTooltip.SIZE = SIZE;

export {FieldTooltip};
