import React from 'react';
import PropTypes from 'prop-types';
import {Button, Icon} from 'blueprint-react';
import {Modal} from './Modal';
import './ConfirmModal.scss';

class ConfirmModal extends React.Component {
    constructor(props) {
        super(props);
        this.state = {
            loading: false,
            error: undefined
        };

        this.errorButton = {
            title: 'LABELS.ok',
            action: this.props.onClose,
            type: Button.TYPE.PRIMARY,
            size: Button.TYPE.SMALL
        };
    }

    handleConfirmAction = () => {
        this.setState({loading: true}, () => {
            return Promise.resolve(this.props.data.confirmAction())
                .then(() => {
                    this.setState({loading: false}, this.props.onClose);
                },
                (error) => {
                    this.setState({loading: false, error: error.text});
                });
        });
    };

    handleCancelAction = () => {
        this.setState({loading: true}, () => {
            return Promise.resolve(this.props.data.cancelAction())
                .then(() => {
                    this.setState({loading: false}, this.props.onClose);
                },
                (error) => {
                    this.setState({loading: false, error: error.text});
                });
        });
    };

    render() {
        if (typeof this.props.data === 'undefined') {
            return null;
        }
        let modal = this.props.data || {};
        const {onClose, ...otherProps} = this.props;
        let notificationDetails;

        let cancelAction = modal.cancelAction ? this.handleCancelAction : onClose;
        let buttons = [{
            title: modal.cancelButtonTitle || 'LABELS.cancel',
            action: cancelAction,
            type: Button.TYPE.PRIMARY,
            size: Button.TYPE.SMALL
        }];

        if (this.state.error) {
            return (
                <Modal className="confirm" buttons={[this.errorButton]} title={'LABELS.error'} {...this.props}>
                    {this.state.error}
                </Modal>
            );
        }

        if (modal.confirmAction) {
            buttons.push({
                title: modal.confirmButtonTitle || 'LABELS.ok',
                action: this.handleConfirmAction,
                size: Button.TYPE.SMALL
            });
        }

        if (modal.doNotify) {
            notificationDetails = (
                <React.Fragment>
                    <div className="notification-title">
                        <Icon className={modal.iconColor} type={Icon.TYPE[modal.iconType]} size={Icon.SIZE.MEDIUM}/>
                        <h4 className="notification-msg-title">{modal.notifyTitle}</h4>
                    </div>
                    <div className="notification-msg">{modal.notifymsg}</div>
                </React.Fragment>
            );
        }

        return (
            <Modal className="confirm" buttons={buttons} onClose={cancelAction} loading={this.state.loading} title={modal.title || 'LABELS.warning'} {...otherProps}>
                {typeof notificationDetails === 'undefined' ? (modal.message || 'LABELS.confirmAction') : notificationDetails}
            </Modal>
        );
    }
}

ConfirmModal.propTypes = {
    onClose: PropTypes.func.isRequired
};

ConfirmModal.propTypes = {
    data: PropTypes.object,

};

export {ConfirmModal};
