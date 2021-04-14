import {Color} from 'blueprint-react';

const APP_INFO = {
    APP_ID: 'NexusDashboard',
    APP_NAME: 'Nexus Dashboard',
    APP_TITLE: 'Nexus Dashboard',
};

const APIC_BACKEND_PROPERTY_ACCESSORS = {
    IMDATA: 'imdata',
    INBAND_MGMT_IPV4: 'inbMgmtAddr',
    INBAND_MGMT_IPV6: 'inbMgmtAddr6',
};

const PREFIX = {
    APP_API: '/appcenter/Cisco/' + APP_INFO.APP_ID + '/api/',
    FIRMWARED_API: '/sedgeapi/v1/firmwared/api/',
    CLUSTERD_API: '/sedgeapi/v1/clusterd/api',
    EVENTMANAGER_API: '/sedgeapi/v1/eventmgr/api/',
    INSTALLER_API: '/sedgeapi/v1/installer/upgrade/',
    K8_API: '/sedgeapi/v1/k8s/api/',
    K8_APPS_API: '/sedgeapi/v1/k8s/apis/apps/',
    APIC_API: '/api/node/class/',
    PFM_API: '/sedgeapi/v1/pfm/api/',
    PFM_API_CPU: '/sedgeapi/v1/pfm/api/',
    APP_VERSION_API: '/api/class/',
    SE_STANDALONE_API: '/api/config/',
    STANDALONE_K8_API: '/sedgeapi/v1/k8s-mon/api/',
    STANDALONE_INSTALLERD_API: '/sedgeapi/v1/installer/api/',
    INTERSIGHT_API: '/sedgeapi/v1/cisco-intersightdc/api/connector/',
    BOOTSTRAP_API: '/bootstrap/',
    CLUSTERSTATUS_API: '/clusterstatus/'
};

const URL = {
    getClusterUrl: PREFIX.APP_API + 'clusters.json',
    applicationList: PREFIX.FIRMWARED_API + 'applications',
    getNamespacesUrl: PREFIX.K8_API + 'namespaces',
    getPodsUrl: PREFIX.K8_API + 'pods',
    getDeploymentUrl: PREFIX.K8_APPS_API + 'deployments',
    getStatefulSetUrl: PREFIX.K8_APPS_API + 'statefulsets',
    getServicesUrl: PREFIX.K8_API + 'services',
    getAuditLogsUrl: PREFIX.EVENTMANAGER_API + 'class/audits',
    getBackupsUrl: PREFIX.EVENTMANAGER_API + 'class/exports',
    getRestoresUrl: PREFIX.EVENTMANAGER_API + 'class/imports',
    getReplicaSetsUrl: PREFIX.K8_APPS_API + 'replicasets',
    getNodesK8sUrl: PREFIX.K8_API + 'nodes',
    NODE_PREFIX: PREFIX.APP_API + 'node/',
    CLUSTER_PREFIX: PREFIX.APP_API + 'cluster/',
    getInBandUrl: PREFIX.APIC_API + 'topSystem.json',
    getManagementInBandEPGUrl: PREFIX.APIC_API + 'mgmtInB.json',
    getManagementInBandEPGFaultUrl: '/api/node/mo/uni/tn-mgmt/mgmtp-default/inb-default.json?rsp-subtree-include=faults,no-scoped',
    hardwareResource: PREFIX.PFM_API,
    cpuUsage: PREFIX.PFM_API_CPU + 'cpuusage/',
    getClusterdUrl: PREFIX.CLUSTERD_API + 'config',
    getAppVersionUrl: PREFIX.APP_VERSION_API + 'apPlugin.json',
    // Standalone API's
    login: '/login',
    logout: '/logout',
    refresh: '/refresh',
    logindomains: '/getlogindomains',
    firmwareUpgrade: PREFIX.STANDALONE_INSTALLERD_API + 'upgrade',
    firmwareInstall: PREFIX.STANDALONE_INSTALLERD_API + 'install',
    // installerd API's
    imports: PREFIX.FIRMWARED_API + 'imports',
    uploads: PREFIX.FIRMWARED_API + 'uploads',
    firmwareImages: PREFIX.FIRMWARED_API + 'images',
    // K8
    pods: PREFIX.STANDALONE_K8_API + 'pod',
    container: PREFIX.STANDALONE_K8_API + 'container',
    replicasets: PREFIX.STANDALONE_K8_API + 'replicaset',
    services: PREFIX.STANDALONE_K8_API + 'service',
    namespaces: PREFIX.STANDALONE_K8_API + 'namespace',
    deployments: PREFIX.STANDALONE_K8_API + 'deployment',
    statefulsets: PREFIX.STANDALONE_K8_API + 'statefulset',
    daemonsets: PREFIX.STANDALONE_K8_API + 'daemonset',
    clusterHealth: PREFIX.STANDALONE_K8_API + 'sehealth',
    monNode: PREFIX.STANDALONE_K8_API + 'node/',
    // Localusers API's
    listLocalUsers: PREFIX.SE_STANDALONE_API + 'class/localusers/',
    listRemoteUsers: PREFIX.SE_STANDALONE_API + 'class/remoteusers/',
    localUser: PREFIX.SE_STANDALONE_API + 'dn/localusers/',
    createLocalUser: PREFIX.SE_STANDALONE_API + 'localusers/',
    deleteLocalUser: PREFIX.SE_STANDALONE_API + 'localusers/',
    // TODO: uodate when API is ready
    deleteRemoteUser: PREFIX.SE_STANDALONE_API + 'remoteusers/',
    // Fabric/Site API's
    sitesList: PREFIX.SE_STANDALONE_API + 'class/sites/',
    site: PREFIX.SE_STANDALONE_API + 'dn/sites/',
    createSite: PREFIX.SE_STANDALONE_API + 'addsite/',
    deleteSite: PREFIX.SE_STANDALONE_API + 'deletesite/',
    modifySite: PREFIX.SE_STANDALONE_API + 'modifysite/',
    // LoginDomain API's
    listLoginDomain: PREFIX.SE_STANDALONE_API + 'class/logindomain/',
    loginDomain: PREFIX.SE_STANDALONE_API + 'dn/logindomain/',
    createLoginDomain: PREFIX.SE_STANDALONE_API + 'logindomain/',
    defaultDomain: PREFIX.SE_STANDALONE_API + 'defaultauth/default',
    getDefaultAuth: PREFIX.SE_STANDALONE_API + '/class/defaultauth',
    deleteLoginDomain: PREFIX.SE_STANDALONE_API + 'logindomain/',
    // login provider validity API
    authCheck: '/authcheck',
    // node manager
    nodesList: PREFIX.SE_STANDALONE_API + 'class/nodes/',
    node: PREFIX.SE_STANDALONE_API + 'dn/nodes/',
    createNode: PREFIX.SE_STANDALONE_API + 'nodes/',
    deleteNode: PREFIX.SE_STANDALONE_API + 'nodes/',
    replaceNode: PREFIX.SE_STANDALONE_API + 'rmanode/',
    failOverNode: PREFIX.SE_STANDALONE_API + 'failovernode/',
    rebootNode: PREFIX.SE_STANDALONE_API + 'rebootnode/',
    // cluster API's
    cluster: PREFIX.SE_STANDALONE_API + 'class/cluster/',
    configCluster: PREFIX.SE_STANDALONE_API + 'cluster/',
    // bootstrap status
    bootstrapCimc: PREFIX.BOOTSTRAP_API + 'cimc',
    bootstrapCluster: PREFIX.BOOTSTRAP_API + 'cluster',
    bootstrapNode: PREFIX.BOOTSTRAP_API + 'node',
    bootstrapRma: PREFIX.BOOTSTRAP_API + 'rma',
    clusterVersion: '/version.json',
    // static route API's
    getRoutes: PREFIX.SE_STANDALONE_API + 'class/routes/',
    configRoutes: PREFIX.SE_STANDALONE_API + 'routes/',
    // tech support
    getAllTechSupports: PREFIX.SE_STANDALONE_API + 'class/techsupport/',
    getTechSupport: PREFIX.SE_STANDALONE_API + 'dn/techsupport/',
    collectTechSupport: PREFIX.SE_STANDALONE_API + 'collecttechsupport/',
    deleteTechSupport: PREFIX.SE_STANDALONE_API + 'techsupport/',
    // backup & restore
    getExports: PREFIX.SE_STANDALONE_API + 'class/exports/',
    getImports: PREFIX.SE_STANDALONE_API + 'class/imports/',
    backupConfiguration: PREFIX.SE_STANDALONE_API + 'exports/',
    restoreConfiguration: PREFIX.SE_STANDALONE_API + 'imports/',
    deleteBackup: PREFIX.SE_STANDALONE_API,
    deleteRestore: PREFIX.SE_STANDALONE_API,
    // intersight
    intersightSystems: PREFIX.INTERSIGHT_API + 'Systems',
    // all resource profile
    getAppProfiles: PREFIX.SE_STANDALONE_API + 'dn/apps/',
    createInstance: PREFIX.SE_STANDALONE_API + 'createinstance',
    deleteInstance: PREFIX.SE_STANDALONE_API + 'delinstance',
    restartInstance: PREFIX.SE_STANDALONE_API + 'restartinstance',
    updateInstance: PREFIX.SE_STANDALONE_API + 'updateinstance',
    getAppInfraServices: PREFIX.SE_STANDALONE_API + 'class/apps',
    getAllAppInstances: PREFIX.SE_STANDALONE_API + 'class/appinstances',
    getActiveResourceProfile: PREFIX.SE_STANDALONE_API + 'dn/appinstances/',
    // security policy
    securityPol: PREFIX.SE_STANDALONE_API + 'dn/apigwcfg/default?showPassword=yes',
    updateSecurityPol: PREFIX.SE_STANDALONE_API + 'apigwcfg/default',
    // Logged in Node
    nodeLoggedIn: 'sedgeapi/v1/clusterd/api/members',
    // API doc's
    apiDoc: '/api-doc.lst',
    // ND and sites
    // ndSites: '/v2/atomix/apic-kernel/tags/list',
    imageList: '/query?query={ImageListWithLatestTag(){Name%20Latest%20Description%20Vendor%20Licenses%20Labels%20Size%20LastUpdated}}',
    ndSite: PREFIX.SE_STANDALONE_API + 'dn/v2/sites/',
    ndModifySites: PREFIX.SE_STANDALONE_API + 'v2/modifysite/',
    ndDeleteSites: PREFIX.SE_STANDALONE_API + 'v2/deletesite/',
    ndAddSites: PREFIX.SE_STANDALONE_API + 'v2/addsite/',
    dcnmpreboard: PREFIX.SE_STANDALONE_API + 'dcnmpreboard/'
};

const STATUS_TYPE = {
    SUCCESS: 'status-success',
    WARNING: 'status-warning',
    ERROR: 'status-error',
    UNKNOWN: 'status-unknown',
    INFO: 'status-info',
    MAJOR: 'status-major',
    MINOR: 'status-minor',
    NA: 'status-unknown',
    ANOMALYOK: 'anomaly-status-success',
    ANOMALYINFO: 'anomaly-status-info',
    ANOMALYWARNING: 'anomaly-status-warning',
    ANOMALYMINOR: 'anomaly-status-minor',
    ANOMALYMAJOR: 'anomaly-status-major',
    ANOMALYCRITICAL: 'anomaly-status-error',
    ANOMALYUNKNOWN: 'anomaly-status-unknown',
    ANOMALYNA: 'status-na',
};

// const COLOR_NAMES = Color.names;

// random colors that do not represent status
const RANDOM_COLORS = [
    '#' + Color.names.blue,
    '#' + Color.names.goldenrod,
    '#' + Color.names.blueviolet,
    '#' + Color.names.brown,
    '#' + Color.names.coral,
    '#' + Color.names.cyan,
    '#' + Color.names.lightblue,
    '#' + Color.names.magenta,
    '#' + Color.names.navy,
    '#' + Color.names.pink,
    '#' + Color.names.purple,
];

const STATUS_COLOR = {
    [STATUS_TYPE.SUCCESS]: '#6cc04a', // status-green
    [STATUS_TYPE.WARNING]: '#ffcc00', // status-yellow
    [STATUS_TYPE.ERROR]: '#e2231a', // status-red
    [STATUS_TYPE.MAJOR]: '#fbab18', // status-orange
};

const STATUS_TYPE_DICTIONARY = {
    // success
    running: STATUS_TYPE.SUCCESS,
    success: STATUS_TYPE.SUCCESS,
    up: STATUS_TYPE.SUCCESS,
    active: STATUS_TYPE.SUCCESS,
    connected: STATUS_TYPE.SUCCESS,
    enabled: STATUS_TYPE.SUCCESS,
    disabled: STATUS_TYPE.SUCCESS,
    alive: STATUS_TYPE.SUCCESS,
    available: STATUS_TYPE.SUCCESS,
    ok: STATUS_TYPE.SUCCESS,
    ready: STATUS_TYPE.SUCCESS,
    'in service': STATUS_TYPE.SUCCESS,
    healthy: STATUS_TYPE.SUCCESS,
    done: STATUS_TYPE.SUCCESS,
    downloaded: STATUS_TYPE.SUCCESS,
    completed: STATUS_TYPE.SUCCESS,

    // unknown
    unknown: STATUS_TYPE.UNKNOWN,

    // warning
    warning: STATUS_TYPE.WARNING,
    pending: STATUS_TYPE.WARNING,
    waiting: STATUS_TYPE.WARNING,
    terminated: STATUS_TYPE.WARNING,
    'out of service': STATUS_TYPE.WARNING,
    'not ready': STATUS_TYPE.WARNING,
    undiscovered: STATUS_TYPE.WARNING,
    unavailable: STATUS_TYPE.WARNING,
    inactive: STATUS_TYPE.WARNING,
    triggered: STATUS_TYPE.WARNING,
    inprogress: STATUS_TYPE.WARNING,

    // health status minor
    minor: STATUS_TYPE.MINOR,

    // major
    major: STATUS_TYPE.MAJOR,

    // info
    unregistered: STATUS_TYPE.INFO,
    download: STATUS_TYPE.INFO,

    // error
    failed: STATUS_TYPE.ERROR,
    critical: STATUS_TYPE.ERROR,
    down: STATUS_TYPE.ERROR,

    // anomaly
    anomalyhealthy: STATUS_TYPE.ANOMALYOK,
    anomalyinfo: STATUS_TYPE.ANOMALYINFO,
    anomalywarning: STATUS_TYPE.ANOMALYWARNING,
    anomalyminor: STATUS_TYPE.ANOMALYMINOR,
    anomalymajor: STATUS_TYPE.ANOMALYMAJOR,
    anomalycritical: STATUS_TYPE.ANOMALYCRITICAL,
    anomalyunknown: STATUS_TYPE.ANOMALYUNKNOWN,
    anomalyna: STATUS_TYPE.ANOMALYNA,
    na: STATUS_TYPE.UNKNOWN
};

const STATUS_TYPE_MAP = new Proxy(STATUS_TYPE_DICTIONARY, {
    get: function(target, property) {
        const propLowercase = property && property.toLowerCase();
        return (propLowercase && target[propLowercase]) || STATUS_TYPE.UNKNOWN;
    },
});

const HEALTH_SEVERITY = {
    CRITICAL: 'health-critical',
    MAJOR: 'health-major',
    MINOR: 'health-minor',
    OK: 'health-ok',
    UNKNOWN: 'health-unknown',
    WARNING: 'health-warning',
    NA: 'health-unknown',
    ANOMALYOK: 'health-anomaly-ok',
    ANOMALYMINOR: 'health-anomaly-minor',
    ANOMALYMAJOR: 'health-anomaly-major',
    ANOMALYCRITICAL: 'health-anomaly-critical',
    ANOMALYUNKNOWN: 'health-anomaly-unknown',
    ANOMALYINFO: 'health-anomaly-info',
    ANOMALYWARNING: 'health-anomaly-warning',
    ANOMALYNA: 'health-anomaly-unknown',
};

const HEALTH_LABEL = {
    [HEALTH_SEVERITY.CRITICAL]: 'Critical',
    [HEALTH_SEVERITY.MAJOR]: 'Major',
    [HEALTH_SEVERITY.MINOR]: 'Minor',
    [HEALTH_SEVERITY.OK]: 'healthy',
    [HEALTH_SEVERITY.UNKNOWN]: 'unknown',
    [HEALTH_SEVERITY.WARNING]: 'warning',
    [HEALTH_SEVERITY.NA]: 'na',

    [HEALTH_SEVERITY.ANOMALYOK]: 'healthy',
    [HEALTH_SEVERITY.ANOMALYINFO]: 'info',
    [HEALTH_SEVERITY.ANOMALYMAJOR]: 'Major',
    [HEALTH_SEVERITY.ANOMALYMINOR]: 'Minor',
    [HEALTH_SEVERITY.ANOMALYCRITICAL]: 'Critical',
    [HEALTH_SEVERITY.ANOMALYUNKNOWN]: 'unknown',
    [HEALTH_SEVERITY.ANOMALYWARNING]: 'warning',
    [HEALTH_SEVERITY.ANOMALYNA]: 'na',
};

// get health severity by status
const HEALTH_SEVERITY_MAP = new Proxy(STATUS_TYPE_MAP, {
    get: function(target, property) {
        switch (target[property]) {
            case STATUS_TYPE.SUCCESS:
                return HEALTH_SEVERITY.OK;
            case STATUS_TYPE.MINOR:
                return HEALTH_SEVERITY.MINOR;
            case STATUS_TYPE.WARNING:
                return HEALTH_SEVERITY.WARNING;
            case STATUS_TYPE.MAJOR:
                return HEALTH_SEVERITY.MAJOR;
            case STATUS_TYPE.ERROR:
                return HEALTH_SEVERITY.CRITICAL;
            case STATUS_TYPE.UNKNOWN:
                return HEALTH_SEVERITY.UNKNOWN;
            case STATUS_TYPE.NA:
                return HEALTH_SEVERITY.NA;
            case STATUS_TYPE.ANOMALYOK:
                return HEALTH_SEVERITY.ANOMALYOK;
            case STATUS_TYPE.ANOMALYINFO:
                return HEALTH_SEVERITY.ANOMALYINFO;
            case STATUS_TYPE.ANOMALYWARNING:
                return HEALTH_SEVERITY.ANOMALYWARNING;
            case STATUS_TYPE.ANOMALYMINOR:
                return HEALTH_SEVERITY.ANOMALYMINOR;
            case STATUS_TYPE.ANOMALYMAJOR:
                return HEALTH_SEVERITY.ANOMALYMAJOR;
            case STATUS_TYPE.ANOMALYCRITICAL:
                return HEALTH_SEVERITY.ANOMALYCRITICAL;
            case STATUS_TYPE.ANOMALYUNKNOWN:
                return HEALTH_SEVERITY.ANOMALYUNKNOWN;
            case STATUS_TYPE.ANOMALYNA:
                return HEALTH_SEVERITY.ANOMALYNA;
            default:
                return '';
        }
    },
});

const POD_STATUS = {
    READY: 'Ready',
    RUNNING: 'Running',
    FAILED: 'Failed',
    PENDING: 'Pending',
};

const AUTH_STATUS = {
    ADMIN: 'admin',
    READ_ONLY_ADMIN: 'read-only-admin',
    DASHBOARD_USER: 'dashboard-user',
    AAA_USER: 'aaa-user',
    SITE_ADMIN_USER: 'site-admin-user',
    SITE_POLICY_USER: 'site-policy-user',
    CONFIG_MANAGER_USER: 'config-manager-user',
};

const USER_ROLES = {
    ADMIN_USER: 'Admin User',
    DASHBOARD_USER: 'Dashboard User',
    AAA_USER: 'AAA User',
    SITE_ADMIN_USER: 'Site Admin User',
    SITE_POLICY_USER: 'Site Policy User',
    CONFIG_MANAGER_USER: 'Config Manager User'
};

const ADMIN_WRITE_RBAC_SINGLE = {
    name: 'admin',
    userPriv: 'WritePriv'
};

const ADMIN_READ_RBAC_SINGLE = {
    name: 'admin',
    userPriv: 'ReadPriv'
};

const AAA_WRITE_RBAC_SINGLE = {
    name: 'aaa',
    userPriv: 'WritePriv'
};

const AAA_READ_RBAC_SINGLE = {
    name: 'aaa',
    userPriv: 'ReadPriv'
};

const SITE_ADMIN_WRITE_RBAC_SINGLE = {
    name: 'site-admin',
    userPriv: 'WritePriv'
};

const SITE_ADMIN_READ_RBAC_SINGLE = {
    name: 'site-admin',
    userPriv: 'ReadPriv'
};

const SITE_POLICY_WRITE_RBAC_SINGLE = {
    name: 'site-policy',
    userPriv: 'WritePriv'
};

const SITE_POLICY_READ_RBAC_SINGLE = {
    name: 'site-policy',
    userPriv: 'ReadPriv'
};

const CONFIG_MANAGER_WRITE_RBAC_SINGLE = {
    name: 'config-manager',
    userPriv: 'WritePriv'
};

const CONFIG_MANAGER_READ_RBAC_SINGLE = {
    name: 'config-manager',
    userPriv: 'ReadPriv'
};

const TENANT_MANAGER_WRITE_RBAC_SINGLE = {
    name: 'tenant-policy',
    userPriv: 'WritePriv'
};

const TENANT_MANAGER_READ_RBAC_SINGLE = {
    name: 'tenant-policy',
    userPriv: 'ReadPriv'
};

const APP_USER_RBAC_SINGLE = {
    name: 'app-user',
    userPriv: 'ReadPriv'
};

const BOOTSTRAP_INSTALLER_STEPS = {
    BEGIN_SETUP: 1,
    CLUSTER_DETAILS: 2,
    NODE_DETAILS: 3,
    REVIEW_DETAILS: 4,
    SHOW_PROGRESS: 5
};

const BOOTSTRAP_PHASE = {
    BOOTSTRAP: 'bootstrap',
    INSTALL: 'install'
};

const BOOTSTRAP_STATUS = {
    PENDING: 'pending',
    IN_PROGRESS: 'inprogress',
    COMPLETED: 'completed',
    FAILED: 'failed'
};

const SERVICES_NAME = {
    cisco_nia: {name: 'Network Insights - Advisor', category: 'Troubleshooting'},
    cisco_nir: {name: 'Network Insights - Resources', category: 'Troubleshooting'},
    cisco_mso: {name: 'Multi-Site Orchestration', category: 'Orchestration'},
    cisco_ni: {name: 'Nexus Insights', category: 'Troubleshooting'},
    default: {name: 'N/A', category: ''},
};

const HEALTH_SCORE_COLOR = {
    Critical: {fill: '#E2231A'},
    Major: {fill: '#FBAB18'},
    Minor: {fill: '#FFCC00'},
    healthy: {fill: '#6CC04A'},
    unknown: {fill: '#58585b'},
    warning: {fill: '#14A792'},
    info: {fill: '#64BBE3'},
    'N/A': {fill: '#58585b'},
};

const SITE_TYPE = {
    ACI: 'ACI',
    DCNM: 'DCNM',
    CLOUD_ACI: 'CloudACI',
};

// TOOD: update app user write as needed
const ROLE_TYPES = {
    adminR: {name: 'Administrator Read', alias: 'admin', rbac: ADMIN_READ_RBAC_SINGLE},
    adminW: {name: 'Administrator Write', alias: 'admin', rbac: ADMIN_WRITE_RBAC_SINGLE},
    aaaR: {name: 'User Manager Read', alias: 'aaa', rbac: AAA_READ_RBAC_SINGLE},
    aaaW: {name: 'User Manager Write', alias: 'aaa', rbac: AAA_WRITE_RBAC_SINGLE},
    appR: {name: 'Dashboard Read', alias: 'app-user', rbac: APP_USER_RBAC_SINGLE},
    appW: {name: 'Dashboard Write', alias: 'app-user', rbac: APP_USER_RBAC_SINGLE},
    siteAdminR: {name: 'Site Administrator Read', alias: 'site-admin', rbac: SITE_ADMIN_READ_RBAC_SINGLE},
    siteAdminW: {name: 'Site Administrator Write', alias: 'site-admin', rbac: SITE_ADMIN_WRITE_RBAC_SINGLE},
    sitePolR: {name: 'Site Manager Read', alias: 'site-policy', rbac: SITE_POLICY_READ_RBAC_SINGLE},
    sitePolW: {name: 'Site Manager Write', alias: 'site-policy', rbac: SITE_POLICY_WRITE_RBAC_SINGLE},
    configMgrR: {name: 'Policy Manager Read', alias: 'config-manager', rbac: CONFIG_MANAGER_READ_RBAC_SINGLE},
    configMgrW: {name: 'Policy Manager Write', alias: 'config-manager', rbac: CONFIG_MANAGER_WRITE_RBAC_SINGLE},
    tenantMgrR: {name: 'Tenant Manager Read', alias: 'tenant-policy', rbac: TENANT_MANAGER_READ_RBAC_SINGLE},
    tenantMgrW: {name: 'Tenant Manager Write', alias: 'tenant-policy', rbac: TENANT_MANAGER_WRITE_RBAC_SINGLE},
};

const ACCESS_BITS = {
    1: 'admin',
    2: 'user-manager',
    3: 'tenant-policy',
    22: 'site-admin',
    23: 'site-policy',
    24: 'policy-manager',
    25: 'app-user',
};

export {APP_INFO, APIC_BACKEND_PROPERTY_ACCESSORS, URL, PREFIX, STATUS_COLOR, STATUS_TYPE, STATUS_TYPE_MAP,
    RANDOM_COLORS, HEALTH_LABEL, HEALTH_SEVERITY, HEALTH_SEVERITY_MAP, POD_STATUS, AUTH_STATUS, USER_ROLES, SERVICES_NAME,
    HEALTH_SCORE_COLOR, SITE_TYPE, ROLE_TYPES, ACCESS_BITS, BOOTSTRAP_INSTALLER_STEPS, BOOTSTRAP_PHASE, BOOTSTRAP_STATUS,
};
