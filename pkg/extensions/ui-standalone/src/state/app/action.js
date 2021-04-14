const GLOBAL_ACTIONS = {
    UPDATE_CLOUD_PROVIDER: 'updateCloudProvider'
};

const LAYOUT_ACTIONS = {
    TOGGLE_CREATE_MENU: 'toggleCreateMenu',
    TOGGLE_SEARCH_COMBO: 'toggleSearchCombo'
};

const SCREEN_ACTIONS = {
    CLOSE_SCREEN: 'closeScreen',
    OPEN_SCREEN: 'openScreen',
    MINIMIZE_SCREEN: 'minimizeScreen',
    CLOSE_MINIMIZED_SCREEN: 'closeMinimizedScreen',
    CLOSE_ALL_MINIMIZED_SCREENS: 'closeAllMinimizedScreens',
    SAVE_SCREEN_TITLE: 'saveScreenTitle',
    WINDOW_RESIZE: 'windowResize'
};

const MODAL_ACTIONS = {
    CLOSE_MODAL: 'closeModal',
    OPEN_MODAL: 'openModal'
};

const GLOBAL_EVENTS = {
    OBJECT_CREATED: 'objectCreated',
    OBJECT_DELETED: 'objectDeleted',
    OBJECT_EDITED: 'objectEdited'
};

const SUMMARY_PANE_ACTIONS = {
    CLOSE_SUMMARY_PANE: 'closeSummaryPane',
    OPEN_SUMMARY_PANE: 'openSummaryPane'
};

const OBJECTS_LIST_PANE_ACTIONS = {
    CLOSE_OBJECTS_LIST_PANE: 'closeObjectsListPane',
    OPEN_OBJECTS_LIST_PANE: 'openObjectsListPane'
};

const GLOBAL_DATA_ACTIONS = {
    CLUSTER_DATA: 'clusterData',
    SERVICE_NODE_DATA: 'serviceNodeData',
    CLUSTER_STATUS: 'clusterStatus',
    BOOTSTRAP_CONFIG: 'bootstrapConfig',
    BOOTSTRAP_NODE_STATUS: 'bootstrapNodeStatus',
};

let globalActions = (dispatch) => {
    return {
        updateCloudProvider: (cloudProvider) => {
            dispatch({type: GLOBAL_ACTIONS.UPDATE_CLOUD_PROVIDER, cloudProvider: cloudProvider});
        }
    };
};

let layoutActions = function(dispatch) {
    return {
        toggleCreateMenu: () => {
            dispatch({type: LAYOUT_ACTIONS.TOGGLE_CREATE_MENU});
        },
        toggleSearchCombo: () => {
            dispatch({type: LAYOUT_ACTIONS.TOGGLE_SEARCH_COMBO});
        }
    };
};

let screenActions = function(dispatch) {
    return {
        closeScreen: () => {
            dispatch({type: SCREEN_ACTIONS.CLOSE_SCREEN});
        },
        closeMinimizedScreen: (id) => {
            dispatch({type: SCREEN_ACTIONS.CLOSE_MINIMIZED_SCREEN, id: id});
        },
        closeAllMinimizedScreens: () => {
            dispatch({type: SCREEN_ACTIONS.CLOSE_ALL_MINIMIZED_SCREENS});
        },
        saveScreenTitle: (id, title) => {
            dispatch({type: SCREEN_ACTIONS.SAVE_SCREEN_TITLE, id: id, title: title});
        },
        minimizeScreen: () => {
            dispatch({type: SCREEN_ACTIONS.MINIMIZE_SCREEN});
        },
        openScreen: (screenData, toBeClosed) => {
            dispatch({type: SCREEN_ACTIONS.OPEN_SCREEN, screenData: screenData, toBeClosed: toBeClosed});
        },
        openDetailsScreen: (moClass, dn, obj) => {
            // this is DETAILS_SCREEN_PREFIX in screens-config, but importing stuff here breaks things
            const screenData = {type: 'details/' + moClass, id: dn, obj};
            dispatch({type: SCREEN_ACTIONS.OPEN_SCREEN, screenData: screenData});
        },
        openCreateScreen: (moClass, contextObjDn) => {
            // this is CREATE_SCREEN_PREFIX in screens-config, but importing stuff here breaks things
            const screenData = {type: 'create/' + moClass, contextObjectDn: contextObjDn};
            dispatch({type: SCREEN_ACTIONS.OPEN_SCREEN, screenData: screenData});
        },
        openEditScreen: (screenData, toBeClosed, onSave) => {
            // this is EDIT_SCREEN_PREFIX in screens-config, but importing stuff here breaks things
            // const screenData = {type: 'edit/' + moClass, id: dn, onSave: onSave};
            dispatch({type: SCREEN_ACTIONS.OPEN_SCREEN, screenData: screenData, toBeClosed: toBeClosed});
        },
        windowResize: (windowSize) => {
            dispatch({type: SCREEN_ACTIONS.WINDOW_RESIZE, windowSize});
        }
    };
};

let modalActions = function(dispatch) {
    return {
        closeModal: () => {
            dispatch({type: MODAL_ACTIONS.CLOSE_MODAL});
        },
        openModal: (modalData) => {
            dispatch({type: MODAL_ACTIONS.OPEN_MODAL, modalData: modalData});
        }
    };
};

let globalDataAction = function(dispatch) {
    return {
        setClusterData: (data) => {
            dispatch({type: GLOBAL_DATA_ACTIONS.CLUSTER_DATA, data: data});
        },
        setServiceNodeData: (data) => {
            dispatch({type: GLOBAL_DATA_ACTIONS.SERVICE_NODE_DATA, data: data});
        },
        // bootstrap cluster status
        setClusterStatus: (data) => {
            dispatch({type: GLOBAL_DATA_ACTIONS.CLUSTER_STATUS, data: data});
        },
        setBootstrapConfig: (data) => {
            dispatch({type: GLOBAL_DATA_ACTIONS.BOOTSTRAP_CONFIG, data: data});
        },
        setBootstrapNodeStatus: (data) => {
            dispatch({type: GLOBAL_DATA_ACTIONS.BOOTSTRAP_NODE_STATUS, data: data});
        }
    };
};

let summaryPaneActions = function(dispatch) {
    return {
        closeSummaryPane: () => {
            dispatch({type: SUMMARY_PANE_ACTIONS.CLOSE_SUMMARY_PANE});
        },
        openSummaryPane: (data) => {
            dispatch({type: OBJECTS_LIST_PANE_ACTIONS.CLOSE_OBJECTS_LIST_PANE});
            dispatch({type: SUMMARY_PANE_ACTIONS.OPEN_SUMMARY_PANE, summaryPaneData: data});
        }
    };
};

let objectsListPaneActions = function(dispatch) {
    return {
        closeObjectsListPane: () => {
            dispatch({type: OBJECTS_LIST_PANE_ACTIONS.CLOSE_OBJECTS_LIST_PANE});
        },
        openObjectsListPane: (data) => {
            dispatch({type: SUMMARY_PANE_ACTIONS.CLOSE_SUMMARY_PANE});
            dispatch({type: OBJECTS_LIST_PANE_ACTIONS.OPEN_OBJECTS_LIST_PANE, data: data});
        }
    };
};

let globalEventsActions = function(dispatch) {
    return {
        signalObjectCreatedEvent: (moCLass) => {
            dispatch({type: GLOBAL_EVENTS.OBJECT_CREATED, moClass: moCLass});
        },
        signalObjectDeletedEvent: (moCLass) => {
            dispatch({type: GLOBAL_EVENTS.OBJECT_DELETED, moClass: moCLass});
        },
        signalObjectEditedEvent: (moCLass) => {
            dispatch({type: GLOBAL_EVENTS.OBJECT_EDITED, moClass: moCLass});
        }
    };
};

let merge = function(actions) {
    return (dispatch) => {
        let actionMap = {};
        actions.forEach((fn) => {
            actionMap = Object.assign({}, actionMap, fn(dispatch));
        });
        return actionMap;
    };
};

let appActions = {
    GLOBAL_ACTIONS: globalActions,
    MODAL_ACTIONS: modalActions,
    SCREEN_ACTIONS: screenActions,
    LAYOUT_ACTIONS: layoutActions,
    SUMMARY_PANE_ACTIONS: summaryPaneActions,
    OBJECTS_LIST_PANE_ACTIONS: objectsListPaneActions,
    GLOBAL_EVENTS_ACTIONS: globalEventsActions,
    GLOBAL_DATA_ACTIONS: globalDataAction,
    merge: merge
};

export {appActions, GLOBAL_ACTIONS, LAYOUT_ACTIONS, SCREEN_ACTIONS, MODAL_ACTIONS, SUMMARY_PANE_ACTIONS, OBJECTS_LIST_PANE_ACTIONS, GLOBAL_EVENTS, GLOBAL_DATA_ACTIONS};
