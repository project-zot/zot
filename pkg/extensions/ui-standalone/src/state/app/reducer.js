import {
    MODAL_ACTIONS,
    SCREEN_ACTIONS,
    LAYOUT_ACTIONS,
    SUMMARY_PANE_ACTIONS,
    OBJECTS_LIST_PANE_ACTIONS,
    GLOBAL_EVENTS,
    GLOBAL_ACTIONS,
    GLOBAL_DATA_ACTIONS
} from './action';
import _, {isEmpty} from 'lodash';

const initialState = {
    aaaLogin: null,
    cloudProvider: null,
    showCreateMenu: true,
    showSearchCombo: false,
    windowSize: {},
    openedScreens: [],
    openedModals: [],
    visibleSummaryPane: undefined,
    visibleObjectsListPane: undefined,
    globalEvents: {},
    clusterData: {},
    serviceNodeData: {},
    clusterStatus: {},
    bootstrapConfig: {},
    bootstrapNodeStatus: []
};

const RECOVER_SCREEN_DATA_GLOBALLY = true;

/*
 * @param state
 * @param action
 * @returns {*}
 */
export default function(state = initialState, action = {}) {
    switch (action.type) {
        case GLOBAL_ACTIONS.UPDATE_CLOUD_PROVIDER:
            return Object.assign({}, state, {
                cloudProvider: action.cloudProvider
            });
        case LAYOUT_ACTIONS.TOGGLE_CREATE_MENU:
            return Object.assign({}, state, {
                showCreateMenu: !state.showCreateMenu
            });
        case LAYOUT_ACTIONS.TOGGLE_SEARCH_COMBO:
            return Object.assign({}, state, {
                showSearchCombo: !state.showSearchCombo
            });
        case SCREEN_ACTIONS.CLOSE_SCREEN: {
            let openedScreens = [...state.openedScreens];
            openedScreens.pop();
            return Object.assign({}, state, {
                openedScreens: openedScreens
            });
        }
        case SCREEN_ACTIONS.CLOSE_MINIMIZED_SCREEN: {
            let openedScreens = [...state.openedScreens];
            _.remove(openedScreens, (screen) => screen.key === action.id);
            return Object.assign({}, state, {
                openedScreens: openedScreens
            });
        }
        case SCREEN_ACTIONS.CLOSE_ALL_MINIMIZED_SCREENS: {
            let openedScreens = [...state.openedScreens];
            _.remove(openedScreens, (screen) => screen.minimized);
            return Object.assign({}, state, {
                openedScreens: openedScreens
            });
        }
        case SCREEN_ACTIONS.SAVE_SCREEN_TITLE: {
            let openedScreens = [...state.openedScreens];
            if (openedScreens.length === 0) {
                return state;
            }

            for (let i = 0; i < openedScreens.length; i++) {
                if (openedScreens[i].key === action.id) {
                    openedScreens[i].title = action.title;
                    break;
                }
            }

            return Object.assign({}, state, {
                openedScreens: openedScreens
            });
        }
        case SCREEN_ACTIONS.OPEN_SCREEN: {
            let key = action.screenData.type;
            if (typeof action.screenData.id !== 'undefined') {
                key = key + action.screenData.id;
            }

            let openedScreens = [...state.openedScreens];
            let onClose = action.onClose || _.noop;
            let existingScreenIndex = _.findIndex(openedScreens, (item) => item.key === key);

            if (RECOVER_SCREEN_DATA_GLOBALLY && existingScreenIndex >= 0) {
                openedScreens[existingScreenIndex].minimized = false;
                let removed = openedScreens.splice(existingScreenIndex, 1);
                // Putting the screen back at the top of the stack
                openedScreens.push(removed[0]);
            } else {
                let screen = Object.assign({}, action.screenData, {
                    key: key,
                    toBeClosed: action.toBeClosed,
                    onClose: onClose,
                    minimized: false
                });
                openedScreens.push(screen);
            }

            return Object.assign({}, state, {
                openedScreens: openedScreens,
                // if there was an open summary pane, close it
                visibleSummaryPane: undefined,
                // if there was an open objects list pane, close it
                visibleObjectsListPane: undefined
            });
        }
        case SCREEN_ACTIONS.MINIMIZE_SCREEN: {
            if (state.openedScreens.length === 0) {
                // do nothing if there is no screen open
                return state;
            }

            let openedScreens = [...state.openedScreens];
            // Remove the screen from top of the stack and put it at the bottom
            let minimizingScreen = openedScreens.pop();
            minimizingScreen.minimized = true;
            openedScreens.unshift(minimizingScreen);

            return Object.assign({}, state, {
                openedScreens: openedScreens
            });
        }
        case SCREEN_ACTIONS.WINDOW_RESIZE:
            return Object.assign({}, state, {
                windowSize: Object.assign({}, action.windowSize)
            });
        case MODAL_ACTIONS.OPEN_MODAL:
            return Object.assign({}, state, {
                openedModals: [...state.openedModals, action.modalData]
            });
        case MODAL_ACTIONS.CLOSE_MODAL: {
            let openedModals = [...state.openedModals];
            openedModals.pop();
            return Object.assign({}, state, {
                openedModals: openedModals
            });
        }
        case SUMMARY_PANE_ACTIONS.CLOSE_SUMMARY_PANE:
            return Object.assign({}, state, {
                visibleSummaryPane: undefined
            });
        case SUMMARY_PANE_ACTIONS.OPEN_SUMMARY_PANE:
            return Object.assign({}, state, {
                visibleSummaryPane: Object.assign({}, action.summaryPaneData)
            });
        case OBJECTS_LIST_PANE_ACTIONS.CLOSE_OBJECTS_LIST_PANE:
            return Object.assign({}, state, {
                visibleObjectsListPane: undefined
            });
        case OBJECTS_LIST_PANE_ACTIONS.OPEN_OBJECTS_LIST_PANE:
            return Object.assign({}, state, {
                visibleObjectsListPane: Object.assign({}, action.data)
            });
        case GLOBAL_EVENTS.OBJECT_CREATED:
            return Object.assign({}, state, {
                globalEvents: Object.assign({}, state.globalEvents, {lastCreated: {moClass: action.moClass}})
            });
        case GLOBAL_EVENTS.OBJECT_DELETED:
            return Object.assign({}, state, {
                globalEvents: Object.assign({}, state.globalEvents, {lastDeleted: {moClass: action.moClass}})
            });
        case GLOBAL_EVENTS.OBJECT_EDITED:
            return Object.assign({}, state, {
                globalEvents: Object.assign({}, state.globalEvents, {lastEdited: {moClass: action.moClass}})
            });
        case GLOBAL_DATA_ACTIONS.CLUSTER_DATA:
            return Object.assign({}, state, {clusterData: action.data});
        case GLOBAL_DATA_ACTIONS.SERVICE_NODE_DATA:
            const {data} = action;
            return Object.assign({}, state, {serviceNodeData: data});
        case GLOBAL_DATA_ACTIONS.CLUSTER_STATUS:
            if (!isEmpty(action.data)) {
                return Object.assign({}, state, {
                    clusterStatus: {
                        ...state.clusterStatus,
                        ...action.data
                    }
                });
            }
            return state;
        case GLOBAL_DATA_ACTIONS.BOOTSTRAP_CONFIG:
            return Object.assign({}, state, {bootstrapConfig: action && action.data});
        case GLOBAL_DATA_ACTIONS.BOOTSTRAP_NODE_STATUS:
            return Object.assign({}, state, {bootstrapNodeStatus: action && action.data});
        default:
            return state;
    }
}
