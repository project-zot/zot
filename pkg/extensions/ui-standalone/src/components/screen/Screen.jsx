import React from 'react';
import PropTypes from 'prop-types';
import {noop, isEmpty} from 'lodash';
import {Icon, Button, Modal} from 'blueprint-react';
import LABELS from '../../strings';

import './Screen.scss';

const _CLASSES = {
    SCROLLABLE: 'scrollable'
};

class Screen extends React.Component {
    constructor(props) {
        super(props);

        this.state = {
            showExitConfirmation: this.props.toBeClosed || false
        };

        if (typeof props.saveTitle === 'function') {
            props.saveTitle(props.id, props.title);
        }
    }

    closeScreen = () => {
        if (this.props.confirmOnExit) {
            this.setState({showExitConfirmation: true});
        } else {
            this.props.onClose();
        }
    };

    componentDidUpdate(prevProps) {
        if (this.props.title !== prevProps.title) {
            if (typeof this.props.saveTitle !== 'undefined') {
                this.props.saveTitle(this.props.id, this.props.title);
            }
        }
    }

    renderHeader() {
        let minimizeButton = null;
        if (this.props.minimized) {
            minimizeButton = (
                <div className="minimize-button" onClick={() => {
                    this.props.onMinimize();
                }} title={'LABELS.minimize'}>
                    <Icon type={Icon.TYPE.REMOVE} size={Icon.SIZE.MEDIUM}/>
                </div>
            );
        }
        return (
            <header>
                <h3>{this.props.title}</h3>
                {this.props.allowMinimize && minimizeButton}
                <div className="close-button" onClick={this.closeScreen} title={LABELS.close}>
                    <Icon type={Icon.TYPE.CLOSE} size={Icon.SIZE.MEDIUM}/>
                </div>
            </header>
        );
    }

    renderFooter() {
        const {hideFooter = false, buttons = [{type: Button.TYPE.PRIMARY, size: Button.SIZE.SMALL, action: this.closeScreen, title: '', disabled: false}]} = this.props;
        if (hideFooter) {
            return null;
        }

        const btns = buttons.map((cfg) => {
            const {title, type = Button.TYPE.DEFAULT, disabled, size = Button.SIZE.SMALL, action = noop, ...rest} = cfg;
            return (<Button key={title}
                type={type}
                disabled={disabled}
                size={size}
                onClick={action}
                {...rest}>
                {title}
            </Button>);
        });
        return (
            <footer>
                {btns}
            </footer>
        );
    }

    // ask for confirmation for some particular action on screen
    renderConfirmation = () => {
        let {confirmationMessage, onConfirmationAction, confirmApplyBtnLabel, onConfirmationCancel} = this.props;
        let buttons = [];

        if (isEmpty(confirmationMessage)) {
            return '';
        }

        return (
            <div className="screen-confirmation-container">
                <Modal
                    onClose={onConfirmationCancel}
                    onAction={onConfirmationAction}
                    isOpen={true}
                    excludeCloseIcon={true}
                    applyButtonLabel={confirmApplyBtnLabel}
                    classes={{modal: 'screen-confirmation'}}
                >
                    <div>
                        <div className="screen-confirmation-header">
                            <Icon type={Icon.TYPE.WARNING_OUTLINE} size={Icon.SIZE.MEDIUM}/>
                            <div>{LABELS.warning}</div>
                        </div>
                        <div>{confirmationMessage}</div>
                    </div>
                </Modal>
            </div>
        );
    }

    render() {
        let classes = ['screen-container'];
        if (this.props.fullScroll) {
            classes.push('scrollable');
        }

        if (this.props.minimized) {
            classes.push('minimized');
        }

        return (
            <div className={this.props.className.concat(' ', classes.join(' '))}>
                {this.renderHeader()}
                <main className={this.props.fullScroll ? '' : _CLASSES.SCROLLABLE}>
                    {this.props.children}
                </main>
                {this.renderFooter()}
                {this.renderConfirmation()}
            </div>
        );
    }
}

// type-check props for this component
Screen.propTypes = {
    id: PropTypes.string,
    children: PropTypes.node,
    onClose: PropTypes.func.isRequired,
    onMinimize: PropTypes.func,
    minimized: PropTypes.bool,
    title: PropTypes.string,
    saveTitle: PropTypes.func,
    fullScroll: PropTypes.bool,
    allowMinimize: PropTypes.bool,
    hideFooter: PropTypes.bool,
    buttons: PropTypes.array,
    loading: PropTypes.bool,
    confirmOnExit: PropTypes.bool,
    className: PropTypes.string,
    toBeClosed: PropTypes.bool,

    // confirmation inside screen
    confirmationMessage: PropTypes.oneOfType([PropTypes.object, PropTypes.string]),
    onConfirmationAction: PropTypes.func,
    confirmApplyBtnLabel: PropTypes.string,
    onConfirmationCancel: PropTypes.func,
};

Screen.defaultProps = {
    fullScroll: false,
    allowMinimize: true,
    hideFooter: false,
    buttons: [],
    loading: false,
    confirmOnExit: false,
    className: '',
    minimized: false
};

export {Screen};
