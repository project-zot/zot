import React from 'react';
import PropTypes from 'prop-types';

class ErrorBoundary extends React.Component {
    constructor(props) {
        super(props);
        this.state = {hasError: false};
    }

    componentDidCatch(error, info) {
        this.setState({hasError: true});
    }

    render() {
        const {hasError} = this.state;
        const {message} = this.props;
        if (hasError) {
            return (
                <div>
                    {message}
                </div>
            );
        }
        return this.props.children;
    }
}

export {ErrorBoundary};
