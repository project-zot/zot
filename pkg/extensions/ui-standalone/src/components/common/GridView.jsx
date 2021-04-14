import React from 'react';
import PropTypes from 'prop-types';
import _ from 'lodash';

class GridView extends React.Component {
    constructor(props) {
        super(props);

        this.state = {
            items: this._initializeItems(props.items)
        };
    }

    componentWillReceiveProps(nextProps) {
        this.setState({
            items: this._initializeItems(nextProps.items)
        });
    }

    _initializeItems = (items) => {
        // use value passed in to set select item
        const cells = _.cloneDeep(items);
        cells.forEach((cell) => {
            // Set initial value as false if the client didn't pass selected state
            if (!cell.selected) {
                cell.selected = false;
            }
        });
        return items;
    };

    _handleItemSelect = (cellName, target, e) => {
        // Call onChange only if the component is readOnly
        let {onClick} = this.props,
            items = _.cloneDeep(this.state.items); // new array for setState.
        let selected = null;

        for (let i = 0, l = items.length; i < l; i++) {
            let name = 'grid-cell-' + i;
            if (name === cellName) {
                // Toggle selected
                items[i].selected = !items[i].selected;
            } else {
                items[i].selected = false;
            }

            if (items[i].selected) {
                selected = items[i];
            }
        }

        this.setState({
            items: items
        }, () => {
            // Return the selected list as first param, then passed options with checked key & event
            if (onClick) {
                onClick(selected, items, e);
            }
        });
    };

    _handleAddButtonClick = (cellName, target, e) => {
        this.props.onAddButtonClick(e);
    }

    renderCells = (items) => {
        let Cell = this.props.cell;

        return items.map((item, i) => {
            let key = 'grid-cell-' + i;
            return (
                <Cell name={key} key={key} onClick={this._handleItemSelect} {...item}/>
            );
        });
    };

    render() {
        const Cell = this.props.cell;
        const {required} = this.props;

        return (
            <div className="col-xs-12">
                <p>{this.props.label} {required ? '*' : null}</p>
                <div className="flex flex-left flex-wrap">
                    {this.renderCells(this.props.items)}
                    {this.props.showAddButton ?
                        <Cell name="add-cell-button" heading={this.props.addButtonHeading} showAddButton={true}
                            onClick={this._handleAddButtonClick}/>
                        : null}
                </div>
            </div>
        );
    }
}

GridView.defaultProps = {
    items: [],
    showAddButton: true,
    addButtonHeading: ''
};

GridView.propTypes = {
    items: PropTypes.any,
    onClick: PropTypes.func,
    onAddButtonClick: PropTypes.func,
    cell: PropTypes.any,
    label: PropTypes.string,
    showAddButton: PropTypes.bool,
    addButtonHeading: PropTypes.string
};

export {GridView};
