import React from 'react';
import PropTypes from 'prop-types';

class ModalsRenderer extends React.Component {
    render() {
        if (this.props.openedModals.length === 0) {
            return null;
        }
        const length = this.props.openedModals.length;
        return (
            this.props.openedModals.map((modalData, i) => {
                const ModalComponent = this.props.modalComponents[modalData.type];
                let modalProps = {
                    onClose: this.props.onClose,
                    data: modalData,
                    active: i === length - 1
                };
                return <ModalComponent key={modalData.type} {...modalProps}/>;
            })
        );
    }
}

ModalsRenderer.propTypes = {
    modalComponents: PropTypes.object,
    onClose: PropTypes.func,
    openedModals: PropTypes.array
};

ModalsRenderer.defaultProps = {
    openedModals: []
};

export {ModalsRenderer};
