import {combineReducers} from 'redux';
import app from './app/reducer';
import setup from './setup/reducer';
import sessionReducer from './session/reducer';

const rootReducer = combineReducers({
    app,
    setup,
    session: sessionReducer
});

export default rootReducer;
