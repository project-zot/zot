import {createStore, applyMiddleware} from 'redux';
import rootReducer from './rootReducer';
/* eslint no-underscore-dangle: 0 */
import promiseMiddleware from 'redux-promise-middleware';

export function configureStore(initialState) {
    const store = createStore(rootReducer, window.__REDUX_DEVTOOLS_EXTENSION__ && window.__REDUX_DEVTOOLS_EXTENSION__(), initialState, applyMiddleware(promiseMiddleware()));
    return store;
}

const store = configureStore();

export default store;
