import React from 'react';
import PropTypes from 'prop-types';
import {isEmpty} from 'lodash';
import {Button} from 'blueprint-react';

import {Modal} from '../Modal';
import {FormError} from '../../../components/form/FormError';

import LABELS from '../../../strings';

// import '../about/AboutModal.scss';

class ConfirmationModal extends React.Component {
    constructor() {
        super();
    }

    onDelete = () => {
        const {data: {obj}} = this.props;
        this.props.onClose();
        this.props.data.apiCallBack(obj);
    }

    render() {
        const {data, onClose, ...otherProps} = this.props;
        const targetObj = data.obj;
        const itemNameKey = data && data.itemNameKey || 'name';
        const itemNames = Array.isArray(targetObj) && targetObj.map((obj) => obj[itemNameKey]);
        let msgs = [`${LABELS.confirmationDelete} ${itemNames.join(', ') || data.itemName}?`];
        let cmp;

        if (data.warningMsg) {
            msgs.splice(0, 0, data.warningMsg);
        }
        cmp = (
            <div className="confirmation-body">{msgs.map((msg, i) => {
                return <div key={i}>{msg}</div>;
            })}</div>
        );
        let buttons = [{
            title: LABELS.cancel,
            action: this.props.onClose,
            type: Button.TYPE.DEFAULT,
            size: Button.TYPE.SMALL,
        },
        {
            title: LABELS.ok,
            action: this.onDelete,
            type: Button.TYPE.PRIMARY,
            size: Button.TYPE.SMALL,
        }];
        let classes = ['confirmation-modal'];
        // additional classes passed in from invoker
        if (!isEmpty(data.className)) {
            classes.push(data.className);
        }

        return (
            <Modal className={classes.join(' ')} title={LABELS.confirmDelete} onClose={onClose} buttons={buttons} {...otherProps}>
                {cmp}
            </Modal>
        );
    }
}

ConfirmationModal.propTypes = {
    onClose: PropTypes.func,
    data: PropTypes.object,
    apiCallBack: PropTypes.func
};

export {ConfirmationModal};
