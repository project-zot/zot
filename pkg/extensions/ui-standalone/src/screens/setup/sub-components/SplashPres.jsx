import React from 'react';
import PropTypes from 'prop-types';
import {Button} from 'blueprint-react';
import LABELS from '../../../strings';

const CLASSES = {
    MAIN: 'splash',
    BACKDROP: 'splash-backdrop',
    BUTTON: 'btn--white'
};

import './Splash.scss';

class SplashPres extends React.Component {
    render() {
        return (
            <div className={CLASSES.MAIN}>
                <div className={CLASSES.BACKDROP} />
                <div className="splash-content hero hero__content hero--vibblue">
                    <h1>{LABELS.welcomeCompute}</h1>
                    <p>{LABELS.firstTimeCompute}</p>
                    <Button type={CLASSES.BUTTON} size={Button.SIZE.DEFAULT} onClick={this.props.start}>{LABELS.beginSetup}</Button>
                </div>
            </div>
        );
    }
}

SplashPres.propTypes = {
    start: PropTypes.func
};

export default SplashPres;
