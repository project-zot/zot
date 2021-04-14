import React from 'react';
import {Icon} from 'blueprint-react';
import LABELS from '../strings';

const PATHS = {
    images: '/images',
};

const SIDEBAR_ITEMS = [
    // {
    //     id: 'dashboard',
    //     path: PATHS.nexusDashboard,
    //     title: LABELS.dashboard,
    //     icon: Icon.TYPE.CALL_RATE,
    //     auth: ['admin', 'read-only-admin', 'user-manager', 'site-admin', 'app-user', 'site-policy', 'policy-manager', 'tenant-policy'],
    // },
    // {
    //     id: 'systemDashboard',
    //     path: PATHS.systemOverview,
    //     title: LABELS.systemOverview,
    //     icon: Icon.TYPE.CONFIGURATIONS,
    //     auth: ['admin', 'read-only-admin'],
    // },
    {
        id: 'images',
        path: PATHS.images,
        title: LABELS.images,
        icon: Icon.TYPE.LANGUAGE,
        auth: ['admin', 'read-only-admin']
    },
    // {
    //     id: 'apps',
    //     path: PATHS.apps,
    //     title: 'Service Catalog',
    //     icon: Icon.TYPE.APPS,
    //     auth: ['admin', 'read-only-admin']
    // },
    // {
    //     id: 'systemResources',
    //     path: PATHS.systemResources,
    //     title: LABELS.systemResources,
    //     icon: Icon.TYPE.APPLICATIONS,
    //     auth: ['admin', 'read-only-admin'],
    //     subItems: [
    //         {
    //             id: 'nodes',
    //             path: PATHS.nodes,
    //             title: LABELS.nodes,
    //             auth: ['admin', 'read-only-admin'],
    //         },
    //         {
    //             id: 'pods',
    //             path: PATHS.pods,
    //             title: LABELS.pods,
    //             auth: ['admin', 'read-only-admin'],
    //         },
    //         // {
    //         //     id: LABELS.containers,
    //         //     path: PATHS.containers,
    //         //     title: LABELS.containers
    //         // },
    //         {
    //             id: 'daemonsets',
    //             path: PATHS.daemonsets,
    //             title: LABELS.daemonsets,
    //             auth: ['admin', 'read-only-admin'],
    //         },
    //         {
    //             id: 'deployments',
    //             path: PATHS.deployments,
    //             title: LABELS.deployments,
    //             auth: ['admin', 'read-only-admin'],
    //         },
    //         {
    //             id: 'statefulsets',
    //             path: PATHS.statefulsets,
    //             title: LABELS.statefulsets,
    //             auth: ['admin', 'read-only-admin'],
    //         },
    //         {
    //             id: 'services',
    //             path: PATHS.services,
    //             title: LABELS.services,
    //             auth: ['admin', 'read-only-admin'],
    //         },
    //         {
    //             id: 'namespaces',
    //             path: PATHS.namespaces,
    //             title: LABELS.namespaces,
    //             auth: ['admin', 'read-only-admin'],
    //         }
    //     ]
    // },
    // {
    //     id: 'operations',
    //     path: PATHS.operations,
    //     title: LABELS.operations,
    //     icon: Icon.TYPE.WALLPAPER,
    //     auth: ['admin', 'read-only-admin'],
    //     subItems: [
    //         // {
    //         //     id: 'eventAnalytics',
    //         //     path: PATHS.eventAnalytics,
    //         //     title: LABELS.eventAnalytics,
    //         // },
    //         {
    //             id: 'firmwareManagement',
    //             path: PATHS.firmwareManagement,
    //             title: LABELS.firmwareManagement,
    //             auth: ['admin'],
    //         },
    //         {
    //             id: 'techSupport',
    //             path: PATHS.techSupport,
    //             title: LABELS.techSupport,
    //             auth: ['admin', 'read-only-admin'],
    //         },
    //         {
    //             id: 'auditLogs',
    //             path: PATHS.auditLogs,
    //             title: LABELS.auditLogs,
    //             auth: ['admin', 'read-only-admin'],
    //         },
    //         {
    //             id: 'backupRestore',
    //             path: PATHS.backupRestore,
    //             title: LABELS.backupAmpersandRestore,
    //             auth: ['admin'],
    //         }
    //     ]
    // },
    // {
    //     id: 'infrastructure',
    //     path: PATHS.infrastructure,
    //     title: LABELS.infrastructure,
    //     icon: Icon.TYPE.ANIMATION,
    //     auth: ['admin'],
    //     subItems: [
    //         {
    //             id: 'clusterConfiguration',
    //             path: PATHS.clusterConfiguration,
    //             title: LABELS.clusterConfiguration,
    //             auth: ['admin'],
    //         },
    //         {
    //             id: 'intersight',
    //             path: PATHS.intersight,
    //             title: LABELS.intersight,
    //             auth: ['admin'],
    //         },
    //         {
    //             id: 'appInfraServices',
    //             path: PATHS.appInfraServices,
    //             title: LABELS.appInfraServices,
    //             auth: ['admin'],
    //         },
    //     ]
    // },
    // {
    //     id: 'administrative',
    //     path: PATHS.administrative,
    //     title: LABELS.administrative,
    //     icon: Icon.TYPE.ADMIN,
    //     auth: ['admin', 'user-manager'],
    //     subItems: [
    //         {
    //             id: LABELS.authentication,
    //             path: PATHS.authentication,
    //             title: LABELS.authentication,
    //             auth: ['admin', 'read-only-admin'],
    //         },
    //         {
    //             id: LABELS.security,
    //             path: PATHS.security,
    //             title: LABELS.security,
    //             auth: ['admin'],
    //         },
    //         {
    //             id: 'users',
    //             path: PATHS.users,
    //             title: LABELS.users,
    //             auth: ['admin'],
    //         }
    //     ]
    // }
];

export {PATHS, SIDEBAR_ITEMS};
