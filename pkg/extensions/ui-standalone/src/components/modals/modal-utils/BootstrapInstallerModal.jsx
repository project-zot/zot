import React from 'react';
import PropTypes from 'prop-types';
import {Modal} from 'blueprint-react';

import {BootstrapInstaller} from '../../../standalone/pages/bootstrapInstaller/BootstrapInstaller';

const modalClasses = {
    modal: 'bootstrap-installer-modal',
};

class BootstrapInstallerModal extends React.Component {
    onClose = (event) => {
        const {onClose} = this.props;

        if (onClose) {
            onClose(event);
        }
    }

    render() {
        return (
            <Modal classes={modalClasses} onClose={this.onClose} size={Modal.SIZE.FLUID} title={' '} isOpen={true} footerContent={<div />}>
                <BootstrapInstaller/>
            </Modal>
        );
    }
}

BootstrapInstallerModal.propTypes = {
    onClose: PropTypes.func,
};

export {BootstrapInstallerModal};
