import React from 'react';

import {Modal} from '../Modal';
import {Carousel} from '../../../components/common/Carousel';
import LABELS from '../../../strings';

import './HelpModal.scss';

class HelpModal extends React.Component {
    render() {
        return (
            <Modal {...this.props} title={LABELS.quickStartGuide} hideFooter={true} className="quickstart">
                <Carousel>
                    <div className="quickstart-image cover" />
                    <div className="quickstart-image quick-object-reference" />
                    <div className="quickstart-image quick-access-tools" />
                    <div className="quickstart-image quick-data" />
                </Carousel>
            </Modal>
        );
    }
}

export {HelpModal};
