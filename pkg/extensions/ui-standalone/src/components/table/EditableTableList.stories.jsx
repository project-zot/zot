import React from 'react';
import { storiesOf } from '@storybook/react';
import { EditableTableList } from './EditableTableList';
import { SaveEditableTableList } from './SaveEditableTableList';


storiesOf('Table List Component', module)
  .add('EditableTableList ', () => (

    <EditableTableList
      id="NTP"
      header="NTP Servers"
      subHeader="HostName/IP Address"
      actionLabel="Add NTP Server"
      fieldData={['1.2.3.4']}
    />
  ))
  .add('SaveEditableTableList ', () => (

    <SaveEditableTableList
      id="NTP"
      header="NTP Servers"
      subHeader="HostName/IP Address"
      actionLabel="Add NTP Server"
      fieldData={[]}
    />
  ));