import React from 'react';
import {HEALTH_SEVERITY, URL, RANDOM_COLORS, STATUS_TYPE_MAP,
    STATUS_COLOR, HEALTH_LABEL, AUTH_STATUS, SERVICES_NAME, SITE_TYPE, ROLE_TYPES, ACCESS_BITS,
    BOOTSTRAP_PHASE, BOOTSTRAP_STATUS
} from '../../constants';
import {noop, isEmpty, find} from 'lodash';
import api from '../../common/utils/api';
import LABElS from '../../strings';
import Cookies from 'universal-cookie';

const sessionRefreshConfig = {
    onIdle: noop,
    onReady: noop,
    idleTimer: 60 * 60 * 1000, // an hour to avoid the bug in interceptor code
    verbose: true, // remove it after couple of build
};

const DASHBOARD_ONLY_ROLES = {
    appUsr: 'app-user',
    siteMgr: 'site-policy',
    polMgr: 'policy-manager',
    tenMgr: 'tenant-policy',
};

const cookies = new Cookies();

const uiUtils = {

    getAuthCookie() {
        return cookies.get('AuthCookie') || '';
    },

    removeAuthCookie() {
        cookies.remove('AuthCookie');
    },

    getVersionFromJson(versionJson) {
        let version = '';
        if (versionJson) {
            version = versionJson.major + '.' + versionJson.minor;
            if (versionJson.build) {
                // dev build, make the format <major>.<minor>.<maint>.<build><patch>
                version = version + '.' + versionJson.maintenance + '.' + versionJson.build + versionJson.patch;
            } else {
                // release build, make the for <major>.<minor>(<maint><patch>)
                version = version + '(' + versionJson.maintenance + versionJson.patch + ')';
            }
        }
        return version;
    },

    getEPGNameFromDN(dn) {
        const fullName = dn && dn.split('/') && dn.split('/').pop();
        const name = fullName && fullName.split('inb-') && fullName.split('inb-').pop();

        return !isEmpty(name) ? name : '';
    },

    /* Returns indexes of set bits in number (Note: index returned as <index> + 1)
    * @param number is a (binary) number
    *
    * example input: 1101000000000000000000001
    * example output: [25, 24, 22, 1]
    */
    getSetBits(number) {
        let digits = [...number].reverse().join('');
        let indexes = [], i = -1;

        while ((i = digits.indexOf(1, i + 1)) !== -1) {
            indexes.push(i + 1);
        }
        return indexes;
    },

    getUserAuth(rbac) {
        let accessR = [], accessW = [];
        const userRBAC = rbac && JSON.parse(rbac);
        // default user privilege is admin (TODO: update to lowest privilege once we have all privileges)
        let userType = AUTH_STATUS.ADMIN;
        const authType = userRBAC.find((user) => user.domain === 'all');

        if (!isEmpty(authType)) {
            const {rolesR, rolesW} = authType;
            const readAccessBits =  rolesR.toString(2);
            const writeAccessBits = rolesW.toString(2);

            // get active indices for each role
            let rBits  = this.getSetBits(readAccessBits);
            let wBits  = this.getSetBits(writeAccessBits);

            // get all roles for user (by reading from ACCESS_BITS and generating an array of user roles)
            for (const bit of rBits) {
                if (ACCESS_BITS.hasOwnProperty(bit)) {
                    accessR.push(ACCESS_BITS[bit]);
                }
            }
            for (const bit of wBits) {
                if (ACCESS_BITS.hasOwnProperty(bit)) {
                    accessW.push(ACCESS_BITS[bit]);
                }
            }
        }

        return {
            readPrivs: accessR,
            writePrivs: accessW
        };
    },

    getAppHealth(obj) {
        const {data, operState, error} = obj;
        const operStateLowerCase = operState && operState.toLowerCase();

        if (error || operStateLowerCase === 'failed') {
            return HEALTH_SEVERITY.CRITICAL;
        } else if (operStateLowerCase === 'disabled') {
            return HEALTH_SEVERITY.OK;
        } else {
            return data.usedPods < data.totalPods || (data.usedPods === 0 && data.totalPods === 0) || data.usedContainers < data.totalContainers || (data.usedContainers === 0 && data.totalContainers === 0)
                ? HEALTH_SEVERITY.MINOR
                : HEALTH_SEVERITY.OK;
        }
    },

    isReadOnlyUser(role) {
        const userRole = Object.keys(role)[0];
        let isReadOnlyUser;

        if (userRole) {
            isReadOnlyUser = role[userRole].userPriv === 'ReadPriv' ? true : false;
        }
        return isReadOnlyUser;
    },

    isAdminReadUser(rbac) {
        const isReadOnlyUser = rbac && rbac.readPrivs.includes('admin') && !rbac.writePrivs.includes('admin');
        return isReadOnlyUser;
    },

    // return time elapsed from startTime to finishTime (or now if finishTime is not defined) in seconds
    getTimeElapsed(startTime, finishTime) {
        const startTimeObj = startTime && new Date(startTime);
        const finishTimeObj = finishTime && new Date(finishTime) || Date.now();

        return Math.ceil((finishTimeObj - startTimeObj) / 1000);
    },

    // convert the number timeSpan (seconds) to a readable time string
    // i.e. 4200 => "1 hour 10 minutes", 100 => "2 minutes", 50 => "50 seconds"
    getTimeSpanString(timeSpan) {
        let strSegments = [];
        let timeHours, timeMinutes, timeSeconds;

        if (timeSpan >= 0) {
            timeHours = Math.floor(timeSpan / 3600);
            timeMinutes = Math.floor(timeSpan / 60) % 60;
            timeSeconds = timeSpan % 60;

            if (timeHours) {
                strSegments.push(timeHours);
                strSegments.push('hour' + (timeHours > 1 ? 's' : ''));
            }
            if (timeMinutes) {
                // if minutes is present, seconds will be ignored,
                // so round up if seconds is not zero
                if (timeSeconds > 0) {
                    timeMinutes++;
                }
                strSegments.push(timeMinutes);
                strSegments.push('minute' + (timeMinutes > 1 ? 's' : ''));
            }
            // seconds can be ignored unless time span is less than 1 minute
            if (isEmpty(strSegments)) {
                strSegments.push(timeSeconds);
                strSegments.push('second' + (timeSeconds > 1 ? 's' : ''));
            }
        }

        return strSegments.join(' ');
    },

    getTimeString(timestamp) {
        const timestampConverted = timestamp && new Date(timestamp);
        return (timestampConverted && timestampConverted.toLocaleString('en-CA', {hourCycle: 'h23', dateStyle: 'short', timeStyle: 'medium'})) || '';
    },

    getModTimeString(dataObj) {
        const modts = dataObj && dataObj.meta && dataObj.meta.modts;
        return (modts && this.getTimeString(modts)) || '';
    },

    getCreateTimeString(dataObj) {
        const createts = dataObj && dataObj.meta && dataObj.meta.createts;
        return (createts && this.getTimeString(createts)) || '';
    },

    getNodeRoleCounts(nodeData) {
        let nodeRole = {};
        let chartData = [];

        if (nodeData) {
            nodeData.forEach((node) => {
                nodeRole[node.nodeRole] = (nodeRole[node.nodeRole] || 0) + 1;
            });
            chartData = Object.keys(nodeRole).map((role, index) => {
                return {
                    key: index,
                    name: role,
                    value: nodeRole[role],
                };
            });
        }

        return chartData;
    },

    getCountData(data, accessor) {
        let countObj = {};
        let cumulativeCounts = [];
        let key = accessor || 'status';
        let randomColorIdx = 0;
        let usedColors = [];

        if (!isEmpty(data)) {
            data.map((item) => {
                let status = item[key] || 'unknown';

                countObj[status] = (countObj[status] || 0) + 1;
            });
            cumulativeCounts = Object.keys(countObj).map((status, index) => {
                let color = STATUS_TYPE_MAP[status] && STATUS_COLOR[STATUS_TYPE_MAP[status]];

                if (!color || usedColors.indexOf(color) !== -1) {
                    color = RANDOM_COLORS[randomColorIdx % RANDOM_COLORS.length];
                    randomColorIdx++;
                }
                usedColors.push(color);

                return {
                    key: index,
                    name: status,
                    value: countObj[status],
                    color: color,
                };
            });
        }
        return cumulativeCounts;
    },

    getPodStatus(podStatus) {
        const {status} = podStatus;
        return status;
    },

    groupDataByApp(appData) {
        let data = [];

        appData.forEach((item) => {
            const match = data.find((obj) => obj.name === item.name);
            const index = data.findIndex((obj) => obj.name === item.name);
            let enable = false;

            if (match) {
                item.operState === 'Running' ? (item.isEnable = true) : (item.isEnable = enable);
                match.versionsObj.push({
                    version: item.version,
                    operStage: item.operStage,
                    operState: item.operState,
                    adminState: item.adminState,
                    id: item.id,
                    creationTimestamp: item.creationTimestamp,
                    operErr: item.operErr,
                });
                /*
                 * this case is for when match object is not running and penning update with item object
                 * this condition is to show latest version of the app.
                 */
                if (match.operState !== 'Running' && match.operState !== 'Pending') {
                    if (item.operState !== 'Pending') {
                        data[index] = {...match, operErr: null, ...item};
                    }
                }
                if (item.operState === 'Running') {
                    data[index] = {...match, operErr: null, ...item};
                }
                /*
                 * this case is for multiple upload
                 */
                if (item.operState === 'Pending') {
                    if (match.operState !== 'Running') {
                        data[index] = {...match, operErr: null, ...item};
                    }
                }
            } else {
                item.operState === 'Running' ? (item.isEnable = true) : (item.isEnable = enable);
                item.versionsObj = [
                    {
                        version: item.version,
                        operStage: item.operStage,
                        operState: item.operState,
                        adminState: item.adminState,
                        id: item.id,
                        creationTimestamp: item.creationTimestamp,
                        isEnable: enable,
                        operErr: item.operErr,
                    },
                ];
                data.push(item);
            }
        });

        return data;
    },

    // Utility method to handle error
    getErrorMessage(error, cfg) {
        let errorMsg = '';
        let additionalMsg = null;
        const errorRsp = error && error.response;

        if (cfg) {
            errorMsg = cfg.errorPrefix ? cfg.errorPrefix + ': ' : '';
            additionalMsg = cfg.additionalText ? cfg.additionalText : null;
        }

        if (errorRsp) {
            errorMsg = errorRsp.data && errorRsp.data.error ? errorMsg + ' ' + errorRsp.data.error : errorMsg + ' ' + errorRsp.data;
        }

        // add additional text to first line of error message
        if (additionalMsg) {
            // remove all new line characters
            errorMsg = errorMsg.replace(/(\r\n|\n|\r)/gm, '');
            // check if additionalMsg contains period at the end; before adding errorMsg as next sentence
            if (!additionalMsg.endsWith('.')) {
                errorMsg = additionalMsg + '. ' + errorMsg;
            } else {
                errorMsg = additionalMsg + ' ' + errorMsg;
            }
        }

        // add period to end of sentence
        if (!errorMsg.endsWith('.')) {
            errorMsg = errorMsg + '.';
        }

        return errorMsg;
    },

    // related to getLoggedInNode, accepts sedgeapi/v1/clusterd/api/members response data as parameter
    getCurrentNodeIP(nodeData) {
        let currentNode, ip;
        if (!isEmpty(nodeData)) {
            currentNode = nodeData.find((node) => node.self === true);
            // return oob ip
            ip = currentNode && currentNode.oobNetwork && currentNode.oobNetwork.ifaceIP;
        }

        return ip;
    },

    getLoggedInNode() {
        return new Promise((resolve) => {
            api.get(URL.nodeLoggedIn).then((response) => {
                if (!isEmpty(response.data)) {
                    const activenode = find(response.data, ['self', true]);
                    resolve(activenode);
                }
            });
        });
    },

    cpuUsage(metrics) {
        const cpu = metrics ? metrics.cpuUsage : 0;
        const cpuUsage = cpu * 0.001;
        return cpuUsage.toFixed(2);
    },

    memoryUsage(metrics) {
        const memory = metrics ? metrics.memoryUsage : 0;
        const memoryUsage = Math.round(memory / (1024 * 1024));
        return memoryUsage;
    },

    getSiteHealth(healthScore) {
        let health = LABElS.na;
        if (healthScore) {
            if (healthScore <= 24) {
                health = HEALTH_LABEL[HEALTH_SEVERITY.CRITICAL];
            } else if (healthScore <= 49) {
                health = HEALTH_LABEL[HEALTH_SEVERITY.MAJOR];
            } else if (healthScore <= 75) {
                health = HEALTH_LABEL[HEALTH_SEVERITY.MINOR];
            } else if (healthScore <= 89) {
                health = HEALTH_LABEL[HEALTH_SEVERITY.WARNING];
            } else {
                health = HEALTH_LABEL[HEALTH_SEVERITY.OK];
            }
        }
        return health;
    },

    getAnomanlyScore(anomalyScore) {
        let score = 'anomalyna';
        if (anomalyScore !== undefined && anomalyScore !== null) {
            if (anomalyScore === 0) {
                score = 'anomalyhealthy';
            } else if (anomalyScore <= 20) {
                score = 'anomalyinfo';
            } else if (anomalyScore <= 40) {
                score = 'anomalywarning';
            } else if (anomalyScore <= 60) {
                score = 'anomalyminor';
            } else if (anomalyScore <= 80) {
                score = 'anomalymajor';
            } else if (anomalyScore <= 100) {
                score = 'anomalycritical';
            } else {
                score = 'anomalyunknown';
            }
        }
        return score;
    },

    getAdvisories(advisories) {
        return advisories !== null ? advisories.toString() : LABElS.na;
    },

    getAppDetailsFromFullID(id) {
        let idxF = id.indexOf('-');
        let idxL = id.lastIndexOf(':');
        const name = id.substring(idxF + 1, idxL);
        const version = id.substring(idxL + 1);
        const vendor = id.substring(0, idxF);

        return {
            name: name,
            version: version,
            vendor: vendor,
        };
    },

    // Mapping srms apps to Application names
    getServiceName(service) {
        let applicationName = service.appName ? service.appName.toLowerCase() : 'default';
        const vendor = service.vendor ? service.vendor.toLowerCase() : '';
        // In 2.0 sites.apps will publish vendor and version in addition to appName.
        // Checking for vendor and appending vendor_appName
        if (vendor) {
            if (applicationName === 'nir') {
                applicationName = `${service.vendor}_ni`;
            } else {
                applicationName = `${service.vendor}_${applicationName}`;
            }
        }
        return (
            <div className={`serviceUsed ant-app${applicationName === 'cisco_mso' ? '-others' : ''}`}>
                <span>{!isEmpty(SERVICES_NAME[applicationName]) ? SERVICES_NAME[applicationName].name : SERVICES_NAME.default.name}</span>
            </div>
        );
    },

    getRoleName(role) {
        return (
            <div className={'serviceUsed ant-app small-pill'}>
                <span>{ROLE_TYPES[role] ? ROLE_TYPES[role].name : role}</span>
            </div>
        );
    },

    getRoleAbbreviation(role) {
        let name;
        if (role) {
            switch (role) {
                case 'app-user':
                    name = 'app';
                    break;
                case 'site-admin':
                    name = 'siteAdmin';
                    break;
                case 'site-policy':
                    name = 'sitePol';
                    break;
                case 'config-manager':
                    name = 'configMgr';
                    break;
                case 'tenant-policy':
                    name = 'tenantMgr';
                    break;
                default:
                    name = role;
                    break;
            }
        }
        return name;
    },

    getRolePills(userRoles) {
        let allRoles = [];
        for (let key in userRoles) {
            if (userRoles.hasOwnProperty(key)) {
                const priv = userRoles[key].userPriv === 'ReadPriv' ? 'R' : 'W';
                let roleName = this.getRoleAbbreviation(key);
                roleName = roleName + priv;
                allRoles.push(this.getRoleName(roleName));
            }
        }
        return allRoles;
    },

    /* Checks user rbac to decide if user is dashboard user
    * @param userRbac captures the list of user read and write privileges
    * A user is considered a Dashboard User iff user has (one one or more) of only the following 4 privs:
    * 1 app-user, 2. config-manager, 3. site-manager, 4. tenant-manager
    *
    * set flag to false if user has any rbac (read or write) other than
    * 1. app-user, 2.config-manager, and 3. site-manager, 4. tenant-manager
    */
    isDashboardUser(userRbac) {
        if (!userRbac) {
            return false;
        }

        let rPrivs = userRbac.readPrivs;
        let wPrivs = userRbac.writePrivs;

        rPrivs = rPrivs.filter(priv => (priv !== DASHBOARD_ONLY_ROLES.appUsr && priv !== DASHBOARD_ONLY_ROLES.siteMgr && priv !== DASHBOARD_ONLY_ROLES.polMgr && priv !== DASHBOARD_ONLY_ROLES.tenMgr));
        wPrivs = wPrivs.filter(priv => (priv !== DASHBOARD_ONLY_ROLES.appUsr && priv !== DASHBOARD_ONLY_ROLES.siteMgr && priv !== DASHBOARD_ONLY_ROLES.polMgr && priv !== DASHBOARD_ONLY_ROLES.tenMgr));
        let isDashboardUser = (rPrivs.length === 0 && wPrivs.length === 0) || false;
        return isDashboardUser;
    },

    // Method to get consistent appName
    getAppObject(app) {
        let appName = app.appName ? app.appName.toLowerCase() : '';
        let version = app.version && app.version.substring(0, app.version.indexOf('.') + 2);
        const vendor = app.vendor ? app.vendor.toLowerCase() : '';
        // In 2.0 sites.apps will publish vendor and version in addition to appName.
        // Checking for vendor and appending vendor_appName
        if (vendor) {
            appName = `${vendor}_${appName}`;
        }
        return {appName, version, vendor};
    },

    // Anomanly API call for all sites with app NIR
    getAnomanlyResonse(app, item) {
        if (app.appName === 'cisco_nir') {
            return new Promise((resolve) => {
                api.get(`/sedgeapi/v1/cisco-nir/api/api/telemetry/fabricsSummary.json?fabricName=${item.name}&include=anomalyScore`).then((response) => {
                    if (!isEmpty(response.data)) {
                        resolve(response.data);
                    }
                });
            });
        }
    },

    getAdvisoryResonse(app, item, loginId) {
        let url = '';
        if (app.appName === 'cisco_nia') {
            // Advisories API call for all sites with app NIA
            url = `/sedgeapi/v1/cisco-nia/api/api/nia-activedata-api/v1/advisories.json?userId=${loginId}&fabricId=${item.name}`;
        } else if (app.appName === 'cisco_nir') {
            // Advisories API call for all sites with app NIR version >= 5.0
            if (app.vendor && app.version >= 5.0) {
                url = `/sedgeapi/v1/cisco-nir/api/api/telemetry/advisories/summary.json?fabricName=${item.name}`;
            }
        }

        if (url) {
            return new Promise((resolve) => {
                api.get(url).then((response) => {
                    if (!isEmpty(response.data)) {
                        let advisoryResult = {advisoryTotal: response.data.totalAdvisoryCount || (response.data.infos ? response.data.infos.length : 0), ...response.data};
                        resolve(advisoryResult);
                    }
                });
            });
        } else {
            return null;
        }
    },

    getAppLaunchUrl(app) {
        let url =  window.location.origin;
        if (!isEmpty(app) && app.uiEntrypoint) {
            url = url + app.uiEntrypoint;
        }
        return url;
    },

    isSSOSupported(version = '') {
        if (version) {
            const majorVersion = version.substring(0, version.indexOf('('));
            const minor = version.substring(version.indexOf('(') + 1, version.indexOf(')'));
            const minorVersion = minor.split('.')[0];
            // IMR5
            if (parseFloat(majorVersion) === 4.2 && parseInt(minorVersion.charAt(0), 10) >= 6) {
                return true;
            }
            // Jordan M1
            if (parseFloat(majorVersion) === 5.0 && parseInt(minorVersion.charAt(0), 10) >= 2) {
                return true;
            }
            // Jefferson onwards
            if (parseFloat(majorVersion) >= 5.1) {
                return true;
            }
        }
        return false;
    },

    // Launch URL for ACI, Cloud ACI, DCNM
    getXLaunchURL(controller, nodeReachability, siteType, firmwareVersion) {
        let controllerObj = [], url = '';
        const authCookie = uiUtils.getAuthCookie();
        // Checking for nodeReachability array object
        if (!isEmpty(nodeReachability)) {
            const nodeStatus = nodeReachability.find((obj) => obj.state === 'Up');
            if (!isEmpty(controller) && nodeStatus) {
                controllerObj = controller.find((obj) => nodeStatus.ip === obj.dataIP || nodeStatus.ip === obj.mgmtIP);
            } else {
                controllerObj = controller[0];
            }
        }
        if (!isEmpty(controllerObj) && !isEmpty(controllerObj.mgmtUrl)) {
            url = 'https://' + controllerObj.mgmtUrl;
            if (siteType === SITE_TYPE.DCNM) {
                url = url + `/login.jsp?AuthCookie=${authCookie}`;
            } else if (uiUtils.isSSOSupported(firmwareVersion)) {
                url = url + `/api/xlaunch.json?authtoken=${authCookie}`;
            }
        }

        return url;
    },

    getBootstrapPhase(clusterStatus) {
        if (isEmpty(clusterStatus)) {
            return BOOTSTRAP_PHASE.BOOTSTRAP;
        }
        const {bootstrap, install} = clusterStatus;
        let bootstrapState = bootstrap && bootstrap.state;
        let installState = install && install.state || '';

        bootstrapState = bootstrapState && bootstrapState.toLowerCase() || '';
        installState = installState && installState.toLowerCase() || '';

        if (bootstrapState === BOOTSTRAP_STATUS.COMPLETED ||
            installState === BOOTSTRAP_STATUS.COMPLETED || install && install.overallProgress > 0) {
            return BOOTSTRAP_PHASE.INSTALL;
        }
        return BOOTSTRAP_PHASE.BOOTSTRAP;
    },

    // overall bootstrap progress:
    // pending: show bootstrap config
    // in-progress/failed/completed: show bootstrap progress
    getBootstrapStatus(clusterStatus) {
        if (isEmpty(clusterStatus)) {
            return '';
        }

        const {bootstrap, install} = clusterStatus;
        let bootstrapState = bootstrap && bootstrap.state;
        let installState = install && install.state || '';

        bootstrapState = bootstrapState && bootstrapState.toLowerCase() || '';
        installState = installState && installState.toLowerCase() || '';
        if (installState === BOOTSTRAP_STATUS.COMPLETED) {
            return BOOTSTRAP_STATUS.COMPLETED;
        }
        if (installState === BOOTSTRAP_STATUS.FAILED || bootstrapState === BOOTSTRAP_STATUS.FAILED) {
            return BOOTSTRAP_STATUS.FAILED;
        }

        if (bootstrapState || installState) {
            return BOOTSTRAP_STATUS.IN_PROGRESS; // pending, in progress, failed
        }

        return BOOTSTRAP_STATUS.PENDING;
    },

    isUpgradeMode(clusterStatus) {
        if (isEmpty(clusterStatus)) {
            return false;
        }
        const {install} = clusterStatus;
        const clusterConfig = install && install.clusterConfig || {};

        return install && (install.upgradeInProgress || clusterConfig.clusterVersion !== clusterConfig.systemVersion);
    },

    isBootstrapInstallMode(clusterStatus) {
        const bootstrapStatus = uiUtils.getBootstrapStatus(clusterStatus);
        const isUpgradeMode = uiUtils.isUpgradeMode(clusterStatus);
        if (!isUpgradeMode && bootstrapStatus && bootstrapStatus !== BOOTSTRAP_STATUS.COMPLETED && bootstrapStatus !== BOOTSTRAP_STATUS.FAILED) {
            return true;
        }
        return false;
    },

    markerStatus(healthScore, anomalyScore, connectivity) {
        let aScore = this.getAnomanlyScore(anomalyScore);
        if (healthScore === 'Critical' || connectivity === 'Down' || aScore === 'anomalycritical') {
            return 'Critical';
        } else if (healthScore === 'Major' || aScore === 'anomalymajor') {
            return 'Major';
        } else if (healthScore === 'Minor' || aScore === 'anomalyminor') {
            return 'Minor';
        } else if (healthScore === 'warning' || aScore === 'anomalywarning') {
            return 'warning';
        } else if (aScore === 'anomalyinfo') {
            return 'info';
        } else if (healthScore === 'healthy' && connectivity === 'Up' && (aScore === 'anomalyhealthy' || aScore === 'anomalyna')) {
            return 'healthy';
        } else if (healthScore === 'unknown' && connectivity === 'unknown') {
            return 'unknown';
        }
    },

    // extract the version '1.2.3.4' from the image name
    // i.e. "nd-dk9.2.0.0.13.iso" becomes 2.0.0.13
    getImageVersionFromName(name) {
        let version;

        if (!name) {
            return '';
        }
        version = name.replace(/^[^.]*\./, ''); // i.e. remove the prefix "abc."
        version = version.replace(/\.[^.]*$/, ''); // i.e. remove the suffix ".xyz"

        return version;
    },

    firmwaredVersion(version = '') {
        let vResult = '';
        if (version) {
            const appVersion = version.substring(version.indexOf(':') + 1);
            const majorVersion = appVersion.split('.')[0];
            const minorVersion = appVersion.split('.')[1];
            const result = parseFloat(`${majorVersion}.${minorVersion}`);
            if (result >= 5.0) {
                console.log('version', vResult);
                vResult = result;
            }
        }
        return vResult;
    },

    inventoryCount(obj) {
        const iCount = {leaf: 0, spine: 0};
        if (obj.siteType === SITE_TYPE.DCNM) {
            for (let i = 0; i < obj.dcnm.switches.length; i++) {
                iCount[obj.dcnm.switches[i].switchType.toLowerCase()]++;
            }
        } else if (obj.siteType === SITE_TYPE.ACI) {
            for (let i = 0; i < obj.aci.switches.length; i++) {
                iCount[obj.aci.switches[i].switchType.toLowerCase()]++;
            }
        }
        return iCount;
    },

    getImageTag(tag) {
        return (
            <div className={'serviceUsed ant-app small-pill'}>
                <span>{tag}</span>
            </div>
        );
    },

};

export {uiUtils, sessionRefreshConfig};
