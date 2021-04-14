import React from 'react';
import PropTypes from 'prop-types';
import {Input} from 'blueprint-react';
import LABELS from '../../strings';
import './Topology.scss';
import {RingChart as TopologyGraph} from '../charts/RingChart';

class Topology extends React.Component {
    constructor(props) {
        super(props);
        this.state = {
            filter: '',
            selectedData: props.selectedData
        };
    }

    renderLegend = (id, color, label, iconText = '') => {
        const iconClass = iconText === '' ? 'topology-legend-link' : 'topology-legend-icon';
        return (
            <div className="legend" key={id}>
                <div className={iconClass} style={{backgroundColor: color}}>{iconText}</div>
                <span className="topology-legend-label">{label}</span>
            </div>
        );
    };

    onSearchBarChange = (e) => {
        this.setState({filter: e.target.value});
    };

    onNodeSelect = (item) => {
        this.setState({
            selectedData: item[0]
        });
    };

    getDataForNode = (nodeData, treeData) => {
        switch (nodeData.layer) {
            case 2:
                return this.getDataForLayer2(nodeData, treeData);
            case 1:
                return this.getDataForLayer1(nodeData, treeData);
            default:
                return treeData;
        }
    };

    getDataForLayer2(d, data) {
        const root = data[0];
        const {
            children: layer1Nodes,
            ...rootNodeRest
        } = root;
        let clickedNode = {};
        let clickedNodeChildren = [];

        layer1Nodes.forEach((layer1Node) => {
            let layer2Nodes = layer1Node.children || [];

            if (layer1Node.childrenExtended) {
                layer2Nodes = layer2Nodes.concat(layer1Node.childrenExtended);
            }
            layer2Nodes.forEach((layer2Node) => {
                if (layer2Node.id === d.id) {
                    clickedNode = layer2Node;
                    const {
                        children: rem, // eslint-disable-line no-unused-vars
                        ...layer1NodeRest
                    } = layer1Node;
                    layer1NodeRest.children = [rootNodeRest];
                    clickedNodeChildren.push(layer1NodeRest);
                }
            });
        });
        clickedNode.children = clickedNodeChildren;
        if (clickedNode.childrenExtended) {
            clickedNode.children = clickedNode.children.concat(clickedNode.childrenExtended);
        }

        return [clickedNode];
    }

    getDataForLayer1(d, data) {
        const root = data[0];
        const {
            children: layer1Nodes,
            ...rootNodeRest
        } = root;
        const clickedNode = layer1Nodes.find((node) => node.id === d.id);
        clickedNode.children = clickedNode.children || [];
        clickedNode.children.push(rootNodeRest);
        if (clickedNode.childrenExtended) {
            clickedNode.children = clickedNode.children.concat(clickedNode.childrenExtended);
        }
        return [clickedNode];
    }

    render() {
        const {config} = this.props;
        const {selectedData} = this.state;
        const color = config.color;
        const children = selectedData && selectedData.children || [];
        const displayedChildren = children.filter(child => child.text && child.text.indexOf(this.state.filter) !== -1);

        return (
            <div className="topology-container">
                <div className="topology-graph-container">
                    {
                        this.props.data.length ?
                            <TopologyGraph
                                data={this.props.data}
                                getDataForNode={this.getDataForNode}
                                onNodeSelect={this.props.onNodeSelect || this.onNodeSelect} /> :
                            null
                    }
                </div>
                <div className="topology-info-container">
                    <div className="legends-container">
                        <div><b>{LABELS.topologyLegend}</b></div>
                        {
                            this.props.config.legends.map((legend) =>
                                this.renderLegend(legend.id, color[legend.id], legend.label, legend.iconText))
                        }
                        {
                            this.props.config.links.map((link) =>
                                this.renderLegend(link.id, color[link.id], link.label))
                        }
                    </div>
                    <div className="search-container">
                        <div className="selected-data">
                            {
                                this.renderLegend(selectedData.id, color[selectedData.type], selectedData.text, selectedData.label)
                            }
                        </div>
                        <div className="search-result-container">
                            <Input type={Input.TYPE.SEARCH} size={Input.SIZE.COMPRESSED} value={this.state.filter} onChange={this.onSearchBarChange}/>
                            {
                                displayedChildren.map((child) =>
                                    this.renderLegend(child.id, color[child.type], child.text, child.label))
                            }
                        </div>
                    </div>
                </div>
            </div>
        );
    }
}

Topology.propTypes = {
    data: PropTypes.array.isRequired,
    config: PropTypes.object.isRequired,
    selectedData: PropTypes.object,
    getDataForNode: PropTypes.func,
    onNodeSelect: PropTypes.func
};

export {Topology};
