import React from 'react';
import PropTypes from 'prop-types';
import {Loader} from 'blueprint-react';
import {FaultsWidgetPanel} from '../widgets/faults/FaultsWidgetPanel';
import {HealthWidgetPanel} from '../widgets/health/HealthWidgetPanel';
import {GeneralWidgetPanel} from '../widgets/GeneralWidgetPanel';
import {DetailsWidgetPanel} from '../widgets/DetailsWidgetPanel';
import api from '../../common/utils/api';

class GenericDetailsScreenContent extends React.Component {
    render() {
        const obj = this.props.obj;
        const dn = obj.dn;
        return (
            <main className="row">
                <div className="col-sm-3">
                    <GeneralWidgetPanel obj={obj}/>
                </div>
                <div className="col-sm-6">
                    <DetailsWidgetPanel ulClassName="row" obj={obj} properties={this.props.detailProperties} collapsible={false}/>
                </div>
                <div className="col-sm-3">
                    <HealthWidgetPanel dn={dn}/>
                    <FaultsWidgetPanel dn={dn}/>
                </div>
            </main>
        );
    }
}

GenericDetailsScreenContent.propTypes = {
    obj: PropTypes.object,
    detailProperties: PropTypes.any
};

export {GenericDetailsScreenContent};
