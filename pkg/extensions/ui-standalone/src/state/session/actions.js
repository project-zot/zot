const AUTH_ACTIONS = {
    LOGIN: 'login',
    REFRESH: 'refresh',
    LOGOUT: 'logout'
};

let sessionActions = function(dispatch) {
    return {
        loginAction: (session) => {
            dispatch({type: AUTH_ACTIONS.LOGIN, session});
        },
        refreshAction: (session) => {
            dispatch({type: AUTH_ACTIONS.REFRESH, session});
        },
        logoutAction: () => {
            dispatch({type: AUTH_ACTIONS.LOGOUT});
        }
    };
};

export {sessionActions, AUTH_ACTIONS};
