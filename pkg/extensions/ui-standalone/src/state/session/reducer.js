import {AUTH_ACTIONS} from './actions';

const initialState = null;

export default function sessionReducer(state = initialState, action) {
    switch (action.type) {
        case AUTH_ACTIONS.LOGIN:
        case AUTH_ACTIONS.REFRESH:
            return action.session;
        case AUTH_ACTIONS.LOGOUT:
            return null;
        default:
            return state;
    }
}
