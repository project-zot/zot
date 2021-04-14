
const SETUP_ACTIONS = {
    FINISH_TASK: 'initital-setup-finish-task',
    LOADING: 'initital-setup-loading',
    SPLASH: 'initital-setup-splash',
    START: 'initital-setup-start',
    CLUSTER_SETUP: 'initital-setup-cluster',
    REGION_SETUP: 'initital-setup-regions',
    DNS_SETUP: 'initital-setup-dns',
    SMART_LICENSING_SETUP: 'initial-setup-smart-licensing',
    SUMMARY: 'initital-setup-summary',
    DONE: 'initital-setup-done',
    NTP_SETUP: 'initial-setup-ntp',
    SERVICE_NODE_REGISTRATION: 'initial-setup-servicenoderegistration',
    SAVE_CLUSTER: 'initital-save-cluster',
    EDIT_CLUSTER: 'initital-edit-cluster'
};

const FIRMWARE_SETUP_ACTION = {
    FIRMWARE_OBJ: 'firmware-obj'
};

let firmwareSetupActions = function(dispatch) {
    return {
        firmwareSetup: (data) => {
            dispatch({type: FIRMWARE_SETUP_ACTION.FIRMWARE_OBJ, data});
        }
    };
};

let setupActions = function(dispatch) {
    return {
        loading: () => {
            dispatch({type: SETUP_ACTIONS.LOADING});
        },
        splash: () => {
            dispatch({type: SETUP_ACTIONS.SPLASH});
        },
        start: () => {
            dispatch({type: SETUP_ACTIONS.START});
        },
        clusterSetup: () => {
            dispatch({type: SETUP_ACTIONS.CLUSTER_SETUP});
        },
        regionSetup: () => {
            dispatch({type: SETUP_ACTIONS.REGION_SETUP});
        },
        dnsSetup: () => {
            dispatch({type: SETUP_ACTIONS.DNS_SETUP});
        },
        smartLicensingSetup: () => {
            dispatch({type: SETUP_ACTIONS.SMART_LICENSING_SETUP});
        },
        summary: () => {
            dispatch({type: SETUP_ACTIONS.SUMMARY});
        },
        done: () => {
            dispatch({type: SETUP_ACTIONS.DONE});
        },
        finishTask: (payload) => {
            dispatch({type: SETUP_ACTIONS.FINISH_TASK, data: payload});
        },
        ntpSetup: () => {
            dispatch({type: SETUP_ACTIONS.NTP_SETUP});
        },
        serviceNodeRegistration: () => {
            dispatch({type: SETUP_ACTIONS.SERVICE_NODE_REGISTRATION});
        },
        saveCluster: () => {
            dispatch({type: SETUP_ACTIONS.SAVE});
        },
        editCluster: () => {
            dispatch({type: SETUP_ACTIONS.EDIT_CLUSTER});
        }
    };
};

export {setupActions, firmwareSetupActions, SETUP_ACTIONS, FIRMWARE_SETUP_ACTION};
