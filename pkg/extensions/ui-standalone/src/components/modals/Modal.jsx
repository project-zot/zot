import React from 'react';
import PropTypes from 'prop-types';
import {Icon, Button, LoaderOverlay} from 'blueprint-react';
import {ConfirmModal} from './ConfirmModal';
import LABELS from '../../strings';

import './Modal.scss';

const CLASSES = {
    ACTIVE: 'active',
    MODAL_WRAP: 'modal-wrap',
    MODAL_CONTAINER: 'modal-container',
    SCROLLABLE: 'scrollable',
    CLOSE_BUTTON: 'close-button'
};

class Modal extends React.Component {
    constructor(props) {
        super(props);

        this.state = {
            showExitConfirmation: false
        };
    }

    clickOutside = () => {
        if (this.props.closeOnClickOutside) {
            this.closeModal();
        }
    };

    closeModal = () => {
        if (this.props.confirmOnExit) {
            this.setState({showExitConfirmation: true});
        } else {
            this.props.onClose();
        }
    };

    renderConfirmModal(show) {
        if (!show) {
            return null;
        }
        let modalData = {
            confirmAction: () => {
                this.props.onClose();
            },
            title: 'LABELS.warning',
            message: 'LABELS.warningUnsavedChanges'
        };
        return (
            <ConfirmModal active data={modalData} onClose={() => {
                this.setState({showExitConfirmation: false});
            }}/>
        );
    }

    renderHeader() {
        return (
            <header>
                <h4>{this.props.title}</h4>
                <div className={CLASSES.CLOSE_BUTTON} onClick={this.closeModal} title={LABELS.close}>
                    <Icon type={Icon.TYPE.CLOSE} size={Icon.SIZE.MEDIUM}/>
                </div>
            </header>
        );
    }

    /**
     * @return {String} jsx
     */
    renderFooter = () => {
        // buttons will default to a simple close button if no buttons are passed in.
        const {hideFooter = false, footer = false, buttons = [{type: Button.TYPE.PRIMARY, size: Button.SIZE.SMALL, action: this.closeModal, title: LABELS.close}]} = this.props;
        if (footer) {
            return footer;
        }

        if (hideFooter) {
            return null;
        }

        const btns = buttons.map((cfg) => {
            const {title, type, size, disabled, action} = cfg;
            return (<Button
                key={title}
                type={type || Button.TYPE.DEFAULT}
                size={size || Button.SIZE.SMALL}
                disabled={disabled}
                onClick={action}>{title}</Button>);
        });

        return (<footer>{btns}</footer>);
    };

    render() {
        const {fullScroll = false, active = true, className, loading, children} = this.props;
        const {showExitConfirmation = false} = this.state;
        let classes = [CLASSES.MODAL_WRAP];
        if (fullScroll) {
            classes.push(CLASSES.SCROLLABLE);
        }

        if (active) {
            classes.push(CLASSES.ACTIVE);
        }
        return (
            <div className={classes.join(' ')} onClick={this.clickOutside}>
                <div className={className.concat(' ', CLASSES.MODAL_CONTAINER)}>
                    {this.renderConfirmModal(showExitConfirmation)}
                    {loading ? <LoaderOverlay/> : null}
                    {this.renderHeader()}
                    <main className={fullScroll ? '' : CLASSES.SCROLLABLE}>
                        {children}
                    </main>
                    {this.renderFooter()}
                </div>

            </div>
        );
    }
}

// type-check props for this component
Modal.propTypes = {
    children: PropTypes.node,
    onClose: PropTypes.func.isRequired,
    title: PropTypes.string,
    fullScroll: PropTypes.bool,
    buttons: PropTypes.array,
    loading: PropTypes.bool,
    confirmOnExit: PropTypes.bool,
    closeOnClickOutside: PropTypes.bool,
    className: PropTypes.string,
    active: PropTypes.bool,
    hideFooter: PropTypes.bool,
    footer: PropTypes.node
};

Modal.defaultProps = {
    fullScroll: false,
    loading: false,
    confirmOnExit: false,
    closeOnClickOutside: false,
    className: '',
    active: false
};

export {Modal};
