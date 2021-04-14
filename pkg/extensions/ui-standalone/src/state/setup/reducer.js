import {SETUP_ACTIONS, FIRMWARE_SETUP_ACTION} from './action';

const initialState = {
    screen: SETUP_ACTIONS.LOADING,
    summaryData: {},
    isClusterSaved: false,
    firmwareObj: {}
};

/*
 * @param state
 * @param action
 * @returns {*}
 */
export default function(state = initialState, action = {}) {
    switch (action.type) {
        case SETUP_ACTIONS.LOADING:
        case SETUP_ACTIONS.START:
        case SETUP_ACTIONS.SPLASH:
        case SETUP_ACTIONS.CLUSTER_SETUP:
        case SETUP_ACTIONS.REGION_SETUP:
        case SETUP_ACTIONS.DNS_SETUP:
        case SETUP_ACTIONS.SMART_LICENSING_SETUP:
        case SETUP_ACTIONS.SUMMARY:
        case SETUP_ACTIONS.NTP_SETUP:
        case SETUP_ACTIONS.SERVICE_NODE_REGISTRATION:
        case SETUP_ACTIONS.EDIT_CLUSTER:
            return Object.assign({}, state, {
                screen: action.type
            });
        case SETUP_ACTIONS.FINISH_TASK: {
            const {data} = action;
            return Object.assign({}, state, {
                summaryData: Object.assign({}, state.summaryData, data)
            });
        }
        case SETUP_ACTIONS.DONE:
            return Object.assign({}, state, {
                summaryData: {},
                screen: null
            });
        case SETUP_ACTIONS.SAVE_CLUSTER:
            return Object.assign({}, state, {
                isClusterSaved: true
            });
        case FIRMWARE_SETUP_ACTION.FIRMWARE_OBJ:
            const {data} = action;
            return Object.assign({}, state, {
                firmwareObj: data,
            });
        default:
            return state;
    }
}
