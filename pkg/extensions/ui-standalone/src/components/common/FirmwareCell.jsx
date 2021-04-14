import React from 'react';
import PropTypes from 'prop-types';
import _ from 'lodash';
import './FirmwareCell.scss';

class FirmwareCell extends React.Component {
    constructor(props) {
        super(props);
        this.onClickHandler = this.onClickHandler.bind(this);
        this.checkElement = React.createRef();
    }

    componentDidMount = () => {
        if (this.checkElement.current) {
            this.checkElement.current.selected = !!this.props.selected;
        }
    };

    componentDidUpdate = (prevProps) => {
        if (this.props.selected !== prevProps.selected) {
            this.checkElement.current.selected = this.props.selected;
        }
    };

    onClickHandler = (proxy, evt) => {
        if (this.props.onClick instanceof Function) {
            this.props.onClick(this.props.name, proxy, evt);
        }
    };

    render() {
        let className = '';
        if (this.props.status) {
            className = '-warning';
        }
        if (this.props.selected) {
            className = '-selected';
        }

        return (
            <div ref={this.checkElement} className={'firmware-cell' + className} onClick={this.onClickHandler}>
                <div className="firmware-cell-heading flex flex-center flex-wrap">
                    { this.props.status ?
                        <div className="cell-heading-icon">
                            <span className="icon-warning-outline icon-smaller"/>
                        </div> : null
                    }
                    <div className="cell-heading-text">
                        <span>{this.props.heading}</span>
                    </div>
                </div>
                {this.props.showAddButton ?
                    <div className="add-button-icon flex flex-center flex-wrap">
                        <span className="icon-add-outline icon-medium"/>
                    </div>
                    :
                    <div className="firmware-cell-content">
                        <div className="firmware-cell-title">
                            <span>{this.props.title}</span>
                        </div>
                    </div>
                }
            </div>
        );
    }
}

FirmwareCell.defaultProps = {
    showAddButton: false
};

FirmwareCell.propTypes = {
    selected: PropTypes.bool,
    onClick: PropTypes.func,
    name: PropTypes.string,
    status: PropTypes.string,
    heading: PropTypes.string,
    showAddButton: PropTypes.bool,
    title: PropTypes.string
};

export {FirmwareCell};
