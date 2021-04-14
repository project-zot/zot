import React from 'react';
import PropTypes from 'prop-types';
import {isEmpty} from 'lodash';

import './PlainTable.scss';

const EMPTY_CELL_PLACEHOLDER = '-';

class PlainTable extends React.Component {
    constructor() {
        super();
    }

    getTableHeader() {
        const {columns} = this.props;
        let hasHeader = false;
        const cells = !isEmpty(columns) && columns.map((column, colIdx) => {
            let cellClasses = ['table-cell'];

            hasHeader = hasHeader || !isEmpty(column.Header);
            if (column.className) {
                cellClasses.push(column.className);
            }

            return (
                <th key={'table-header-' + colIdx} className={cellClasses.join(' ')}>
                    <div className="cell-content">{column.Header}</div>
                </th>
            );
        });
        if (hasHeader) {
            return (
                <thead>
                    <tr key={'table-header'} className="table-header">
                        {cells}
                    </tr>
                </thead>
            );
        }
    }

    getRow(rowData, rowIdx) {
        const {columns} = this.props;
        let cells;

        if (isEmpty(columns)) {
            cells = (
                <td key={'table-cell-' + rowIdx} className="table-cell">
                    <div className="cell-content">{rowData}</div>
                </td>
            );
        } else {
            cells = columns.map((column, colIdx) => {
                const {accessor, Cell} = column;
                let cellClasses = ['table-cell'];
                let cellContent;

                if (column.className) {
                    cellClasses.push(column.className);
                }

                if (typeof Cell === 'function') {
                    cellContent = Cell({original: rowData}, rowIdx);
                } else {
                    cellContent = accessor && rowData[accessor] || EMPTY_CELL_PLACEHOLDER;
                }
                return (
                    <td key={'table-cell-' + rowIdx + '-' + colIdx} className={cellClasses.join(' ')}>
                        <div className="cell-content">{cellContent}</div>
                    </td>
                );
            });
        }
        return (
            <tr key={'table-row-' + rowIdx} className="table-row">
                {cells}
            </tr>
        );
    }

    getTableBody() {
        const {data} = this.props;
        let dataRows = data && data.map(this.getRow.bind(this));

        // if (isEmpty(dataRows)) {
        //     dataRows = <tr><td>{LABELS.noData}</td></tr>
        // }
        return (
            <tbody>
                {dataRows}
            </tbody>
        );
    }

    render() {
        const {className} = this.props;
        let classes = ['plain-table'];
        if (className) {
            classes.push(className);
        }
        return (
            <div className={classes.join(' ')}>
                <table>
                    {this.getTableHeader()}
                    {this.getTableBody()}
                </table>
            </div>
        );
    }
}

PlainTable.propTypes = {
    className: PropTypes.string,
    columns: PropTypes.array,
    data: PropTypes.oneOfType([PropTypes.arrayOf(PropTypes.object), PropTypes.arrayOf(PropTypes.string)]).isRequired
};

export {PlainTable};
