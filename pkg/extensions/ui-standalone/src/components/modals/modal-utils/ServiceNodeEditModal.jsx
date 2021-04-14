import React from 'react';
import {isEqual, reduce, extend} from 'lodash';
import PropTypes from 'prop-types';
import {Button} from 'blueprint-react';
import {connect} from 'react-redux';

import {appActions} from '../../../state/app/action';
import {Modal} from '../Modal';
import {ServiceNodeEditForm} from '../../form/ServiceNodeEditForm';
import {FormError} from '../../../components/form/FormError';

import api from '../../../common/utils/api';
import {URL} from '../../../constants';
import LABELS from '../../../strings';

import '../about/AboutModal.scss';

class ServiceNodeEditModal extends React.Component {
    constructor(props) {
        super(props);
        const {data: {obj}} = props;
        this.state = {
            saveBtnDisabled: true,
            originalObj: {oobIP: obj.oobIP, oobGW: obj.oobGW},
            updatedObj: {oobIP: '', oobGW: ''},
            formError: {}
        };
    }

    saveNode = () => {
        const {obj: {name, serial, inbandIP, inbandGW, oobIP, oobGW, nodeRole, registered}} = this.props.data;
        const {updatedObj, originalObj} = this.state;
        const changedValues = reduce(originalObj, (result, value, key) => isEqual(value, updatedObj[key]) ? result : result.concat(key), []);
        const changedObj = changedValues.map((key) => {
            return {[key]: updatedObj[key]};
        });
        const updatedValue = extend.apply({}, changedObj);
        let params = {
            name: name,
            serial: serial,
            inbandIP: inbandIP,
            inbandGW: inbandGW,
            oobIP: updatedValue.oobIP ? updatedValue.oobIP : oobIP,
            oobGW: updatedValue.oobGW ? updatedValue.oobGW : oobGW,
            nodeRole: nodeRole,
            registered: registered
        };
        api.post(URL.createNode, params)
            .then(() => {
                this.onClose();
                this.props.data.successCallBack(true);
            })
            .catch((error) => {
                this.setState({formError: {code: LABELS.error, text: error.response.data.error}});
            });
    }

    validatedData = (obj, isSaved) => {
        let {updatedObj} = this.state;
        updatedObj = {oobIP: obj.oobIP, oobGW: obj.oobGW};
        this.setState({updatedObj: updatedObj, saveBtnDisabled: isSaved});
    }

    onClose = () => {
        this.props.closeModal();
    }

    render() {
        const {data} = this.props;
        const {formError} = this.state;
        let classes = ['edit-modal'];
        let buttons = [{
            title: LABELS.save || 'LABELS.cancel',
            action: this.saveNode,
            type: Button.TYPE.PRIMARY,
            size: Button.TYPE.SMALL,
            disabled: this.state.saveBtnDisabled
        }];

        return (
            <Modal className={classes.join(' ')} title={LABELS.editNodeDetails} onClose={this.onClose} buttons={buttons} active={true} >
                <ServiceNodeEditForm validatedData={this.validatedData} obj={data.obj}/>
                <FormError error={formError} />
            </Modal>
        );
    }
}

ServiceNodeEditModal.propTypes = {
    onClose: PropTypes.func.isRequired,
    data: PropTypes.object,
    closeModal: PropTypes.func
};

const mapDispatchToProps = (dispatch) => ({
    ...appActions.merge([appActions.MODAL_ACTIONS])(dispatch)
});

ServiceNodeEditModal = connect(null, mapDispatchToProps)(ServiceNodeEditModal);

export {ServiceNodeEditModal};
