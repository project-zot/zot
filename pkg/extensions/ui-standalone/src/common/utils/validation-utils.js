import _ from 'lodash';
const V4_UNSET_LOCAL_ADDR = '0.0.0.0';
const V6_UNSET_LOCAL_ADDR = '::';
const IP_REGEX = /^([1-9][0-9]{0,1}|1[013-9][0-9]|12[0-689]|2[01][0-9]|22[0-3])([.]([1-9]{0,1}[0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])){2}[.]([1-9][0-9]{0,1}|1[0-9]{2}|2[0-4][0-9]|25[0-4])$/;
const IP_PORT_REGEX = /^([1-9][0-9]{0,1}|1[013-9][0-9]|12[0-689]|2[01][0-9]|22[0-3])([.]([1-9]{0,1}[0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])){2}[.]([1-9][0-9]{0,1}|1[0-9]{2}|2[0-4][0-9]|25[0-4])(:[0-9]+)?$/;
const IP_PREFIX_REGEX = /^([1-9][0-9]{0,1}|1[013-9][0-9]|12[0-689]|2[01][0-9]|22[0-3])([.]([1-9]{0,1}[0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])){2}[.]([1-9]{0,1}[0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-4])$/;
const RE_SUBNET_STRING = /\/\d{1,2}$/;
// combines forward looking for 3-of-4 of the following: a-z, A-Z, 0-9, -~=+_$*()/#!@%^  ,
// followed by limited to a-z, A-Z, 0-9, -~=+_$*()/#!@%^  ,
// and restricted to 8-64 characters
// eslint-disable-next-line max-len
const PASSWORD_REGEX = /^(((?=.*[a-z])(?=.*[A-Z])(?=.*\d))|((?=.*[a-z])(?=.*[A-Z])(?=.*[ !~@#$%^`&*()_+\-=[\]{};':"\\|,<>\/?]))|((?=.*[a-z])(?=.*\d)(?=.*[ !~@#$%^`&*()_+\-=[\]{};':"\\|,<>\/?]))|((?=.*[A-Z])(?=.*\d)(?=.*[ !~@#$%^`&*()_+\-=[\]{};':"\\|,<>\/?])))[A-Za-z\d !~@#$%^`&*()_+\-=[\]{};':"\\|,<>\/?]{8,64}$/;
const RANGE_REGEX = /^[0-9-]+$/;
const SERIAL_NUMBER_REGEX = /^[A-Z0-9]{11,}$/;
const SITE_ID = /^([1-9]|[1-8][0-9]|9[0-9]|1[01][0-9]|12[0-7])$/;
// match a-z,A-Z, any number, ._- and space.
const SITE_NAME = /^[a-zA-Z0-9\-. _]+$/;
const LOGIN_DOMAIN = /^[a-zA-Z0-9][a-zA-Z0-9_-]{0,63}$/;
const LOCAL_USER_NAME = /^[a-zA-Z0-9.-]{6,15}$/;
const USER_EMAIL = /^(([^<>()\[\]\\.,;:\s@"]+(\.[^<>()\[\]\\.,;:\s@"]+)*)|(".+"))@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}])|(([a-zA-Z\-0-9]+\.)+[a-zA-Z]{2,}))$/;
const HOST_NAME = /^(([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\-]*[a-zA-Z0-9])\.)*([A-Za-z0-9]|[A-Za-z0-9][A-Za-z0-9\-]*[A-Za-z0-9])$/;
const HOST_PORT_NAME = /^(([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\-]*[a-zA-Z0-9])\.)*([A-Za-z0-9]|[A-Za-z0-9][A-Za-z0-9\-]*[A-Za-z0-9])(:[0-9]+)?$/;
const ANY_DIGIT = /\d/;
const ANY_NUMBER = /\d+/;
const ANY_LOWERCASE = /[a-z]/;
const ANY_UPPERCASE = /[A-Z]/;
const ANY_SPL_CHARS = /[ !~@#$%^`&*()_+\-=[\]{};':"\\|,<>\/?]/;
const EPG_NAME = /^[a-zA-Z0-9_.:-]+$/;
const NODE_NAME = /^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$/i;

const V4_V6_IpHostRegex = /^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$|^(([a-zA-Z]|[a-zA-Z][a-zA-Z0-9_\-]*[a-zA-Z0-9_])\.)*([A-Za-z]|[A-Za-z][A-Za-z0-9_\-]*[A-Za-z0-9_])$|^\s*((([0-9A-Fa-f]{1,4}:){7}([0-9A-Fa-f]{1,4}|:))|(([0-9A-Fa-f]{1,4}:){6}(:[0-9A-Fa-f]{1,4}|((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(([0-9A-Fa-f]{1,4}:){5}(((:[0-9A-Fa-f]{1,4}){1,2})|:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(([0-9A-Fa-f]{1,4}:){4}(((:[0-9A-Fa-f]{1,4}){1,3})|((:[0-9A-Fa-f]{1,4})?:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){3}(((:[0-9A-Fa-f]{1,4}){1,4})|((:[0-9A-Fa-f]{1,4}){0,2}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){2}(((:[0-9A-Fa-f]{1,4}){1,5})|((:[0-9A-Fa-f]{1,4}){0,3}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){1}(((:[0-9A-Fa-f]{1,4}){1,6})|((:[0-9A-Fa-f]{1,4}){0,4}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(:(((:[0-9A-Fa-f]{1,4}){1,7})|((:[0-9A-Fa-f]{1,4}){0,5}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:)))(%.+)?\s*$/;

const regexes = {
    RE_SUBNET_STRING
};

const escapeIpwithMask = (val) => {
    let escapeString = '';
    if (!_.isEmpty(val)) {
        escapeString = val.replace('/', '%2f');
    }
    return escapeString;
};

const removeMaskFromIp = (val) => {
    let updatedIp = '';
    if (!_.isEmpty(val)) {
        updatedIp = val.replace(/\/.*$/, '');
    }
    return updatedIp;
};

// remove leading/trailing spaces/tabs/newlines
const removeLeadTrailSpaces = (val) => {
    let newVal = val;

    if (typeof newVal === 'string') {
        newVal = newVal.replace(/^[ \t\n]+/g, '').replace(/[ \t\n]+$/g, '');
    }

    return newVal;
};

const mergeOptions = (defaults, options) => {
    if (options === defaults || _.isEmpty(options)) {
        return defaults;
    }
    return Object.assign({}, defaults, options);
};

const isIpValid = (ip) => {
    if (ip && ip.match(IP_REGEX)) {
        return true;
    }
    return false;
};

const isIpPortValid = (ip) => {
    if (ip && ip.match(IP_PORT_REGEX)) {
        return true;
    }
    return false;
};

const isValidHostName = (host) => {
    if (host && host.match(HOST_NAME)) {
        return true;
    }
    return false;
};

const isValidHostNamePort = (host) => {
    if (host && host.match(HOST_PORT_NAME)) {
        return true;
    }
    return false;
};

const isIpPrefixValid = (ip) => {
    if (ip.match(IP_PREFIX_REGEX)) {
        return true;
    }
    return false;
};

const isValidDigit = (digit) => {
    if (digit.match(ANY_DIGIT)) {
        return true;
    }
    return false;
};

const isUppercase = (char) => {
    if (char.match(ANY_UPPERCASE)) {
        return true;
    }
    return false;
};

const isLowercase = (char) => {
    if (char.match(ANY_LOWERCASE)) {
        return true;
    }
    return false;
};

const isSpecial = (char) => {
    if (char.match(ANY_SPL_CHARS)) {
        return true;
    }
    return false;
};

const isIpAddressDefined = (ipAddress) => {
    return ipAddress && ![V6_UNSET_LOCAL_ADDR, V4_UNSET_LOCAL_ADDR].includes(ipAddress);
};

const maskValid = (address) => {
    let subnet = '/32';
    let subnetMask = 32;

    subnet = RE_SUBNET_STRING.exec(address);

    if (subnet) {
        let parsedSubnet = subnet[0].replace('/', '');
        subnetMask = parseInt(parsedSubnet, 10);
        subnet = '/' + subnetMask;

        if (subnetMask < 0 || subnetMask > 32) {
            return false;
        } else {
            return true;
        }
    }
    return false;
};

const isIpv4MaskValid = (val) => {
    const arr = val.split('/');
    if (arr.length !== 2) {
        return false;
    }

    return isIpValid(arr[0]) && maskValid(val);
};

const isIpv4MaskPrefixValid = (val) => {
    const arr = val.split('/');
    if (arr.length !== 2) {
        return false;
    }

    return isIpPrefixValid(arr[0]) && maskValid(val);
};

const rangeValidation = (range) => {
    // need to validate condition -1
    if (range.match(RANGE_REGEX)) {
        if (range.charAt(0) === '-' || range.charAt(range.length - 1) === '-') {
            return false;
        }
        return true;
    }
    return false;
};

const isRangeValid = (range) => {
    const arr = range.split('-');
    if (arr.length !== 2) {
        return false;
    }
    return rangeValidation(range);
};

const isPasswordValid = (pwd) => {
    if (pwd.match(PASSWORD_REGEX)) {
        return true;
    }
    return false;
};

const isValidName = (name) => {
    if (name.match(/^[a-zA-Z0-9.-]{0,15}$/)) {
        return true;
    }
    return false;
};

const isValidLocalUserName = (name) => {
    if (name.match(LOCAL_USER_NAME)) {
        return true;
    }
    return false;
};

const isValidEmail = (email) => {
    if (email.match(USER_EMAIL)) {
        return true;
    }
    return false;
};

const isValidSiteName = (name) => {
    if (name && name.match(SITE_NAME)) {
        return true;
    }
    return false;
};

const isValidSiteLength = (name) => {
    if (name && (name.length > 0 && name.length <= 128)) {
        return true;
    }
    return false;
};

const isValidInBEpg = (name) => {
    if (name) {
        // user is entering DN - anything allowed iff starts with this format
        if (name.startsWith('uni/tn-mgmt/mgmtp-') && !_.isEmpty(name.split('uni/tn-mgmt/mgmtp-')[1])) {
            return true;
        }
        // user is entering only epg name - must match regex
        if (name.match(EPG_NAME)) {
            return true;
        }
    }
    return false;
};

const isValidLoginDomain = (name) => {
    if (name.match(LOGIN_DOMAIN)) {
        return true;
    }
    return false;
};

const isvalidNumber = (num) => {
    if (num.match(/^\d+$/)) {
        return true;
    }
    return false;
};

const validateSerialNumber = (name) => {
    if (name.match(SERIAL_NUMBER_REGEX)) {
        return true;
    }
    return false;
};

const validSiteId = (id) => {
    if (id && id.match(SITE_ID)) {
        return true;
    }
    return false;
};

const isValidPort = (val) => {
    let num = Number(val);
    return (num >= 1 && num <= 65535) ? true : false;
};

const isValidTimeout = (val) => {
    const num =  Number(val);
    return (num >= 1 && num <= 60) ? true : false;
};

const isValidRetries = (val) => {
    const num =  Number(val);
    return (num >= 0 && num <= 5) ? true : false;
};

const isValidJWTTimeout = (val) => {
    const num =  Number(val);
    return (num >= 300 && num <= 86400) ? true : false;
};

const operationalStages = (operStage) => {
    let stage = '';
    switch (operStage) {
        case 'Initialize':
            stage = 'Initializing';
            break;
        case 'PostInstall':
            stage = 'Finishing installation';
            break;
        case 'PreEnable':
            stage = 'Preparing to enable';
            break;
        case 'Enable':
        case 'EnableInstance':
            stage = 'Enabling';
            break;
        case 'PostEnable':
            stage = 'Finishing enable';
            break;
        case 'PreDisable':
            stage = 'Preparing to disable';
            break;
        case 'Disable':
            stage = 'Disabling';
            break;
        case 'PostDisable':
            stage = 'Finishing disable';
            break;
        case 'PreUninstall':
            stage = 'Preparing to uninstall';
            break;
        case 'Uninstall':
            stage = 'Uninstalling';
            break;
        case 'PreUpgrade':
            stage = 'Preparing to upgrade';
            break;
        case 'PostUpgrade':
            stage = 'Finishing upgrade';
            break;
        case 'Restarting':
            stage = 'Restarting';
            break;
        default:
            stage = stage;
            break;
    }
    return stage;
};

const VALIDATOR_HINT_DICTIONARY = {
    DEFAULT: '',
    PORT: '0-65535',
    HOST: 'i.e. 123.123.123.123 or example.com',
    IPV4: 'i.e. 123.123.123.123',
    IPV4_WITH_MASK: 'i.e. 123.123.123.123/24',
    TIMEOUT: '1-60',
    RETRIES: '0-5',
    PROT_HOST_PORT: 'http[s]://your-proxy.com[:port], port is optional',
    VLAN: '0 or 2-4095',
    NODE_NAME: '1 to 63 characters. Valid characters include letters, digits and hyphen. May not start or end with hyphen.'
};

const VALIDATOR_HINT = new Proxy(VALIDATOR_HINT_DICTIONARY, {
    get: function(target, property) {
        return target[property] || target.DEFAULT;
    }
});

const VALIDATORS = {
    PORT: (value) => {
        let portInteger;

        if (!value || !Number.isInteger(value) && !value.match(ANY_NUMBER)) {
            return VALIDATOR_HINT.PORT;
        }
        portInteger = parseInt(value, 10);
        if (portInteger === isNaN() || portInteger < 0 || portInteger > 65535) {
            return VALIDATOR_HINT.PORT;
        }

        return true;
    },

    HOST: (value) => {
        if (isIpValid(value) || isValidHostName(value)) {
            return true;
        }
        return VALIDATOR_HINT.HOST;
    },

    TIMEOUT: (value) => {
        if (isValidTimeout(value.toString())) {
            return true;
        }
        return VALIDATOR_HINT.TIMEOUT;
    },

    RETRIES: (value) => {
        if (isValidRetries(value)) {
            return true;
        }
        return VALIDATOR_HINT.RETRIES;
    },

    IP_HOST_NAME: (value) => {
        if (isIpValid(value) || isValidHostName(value)) {
            return true;
        }
        return VALIDATOR_HINT.HOST;
    },

    IPV4: (value) => {
        if (isIpValid(value)) {
            return true;
        }
        return VALIDATOR_HINT.IPV4;
    },

    IPV4_WITH_MASK: (value) => {
        if (isIpv4MaskPrefixValid(value)) {
            return true;
        }
        return VALIDATOR_HINT.IPV4_WITH_MASK;
    },

    // i.e. for proxy server, [protocol]://[host]:[port], where port is optional
    PROT_HOST_PORT: (value) => {
        const usage = VALIDATOR_HINT.PROT_HOST_PORT;

        let valueSplit = value && value.split('://');
        if (!valueSplit || valueSplit.length !== 2) {
            return usage;
        }
        let protocol = valueSplit[0].toLowerCase();
        if (protocol !== 'http' && protocol !== 'https') {
            return usage;
        }
        let hostPortSplit = valueSplit[1] && valueSplit[1].split(':');
        if (_.isEmpty(hostPortSplit) || hostPortSplit.length > 2) {
            return usage;
        }
        let host = hostPortSplit[0];
        let port = hostPortSplit[1]; // port is optional
        if (!isIpValid(host) && !isValidHostName(host) ||
            hostPortSplit.length === 2 && VALIDATORS.PORT(port) !== true) {
            return usage;
        }
        return true;
    },

    VLAN: (value) => {
        let vlanInt;

        if (!value || !Number.isInteger(value) && !value.match(ANY_NUMBER)) {
            return VALIDATOR_HINT.VLAN;
        }
        vlanInt = parseInt(value, 10);
        if (vlanInt === isNaN() || vlanInt < 2 && vlanInt !== 0 || vlanInt > 4095) {
            return VALIDATOR_HINT.VLAN;
        }

        return true;
    },

    NODE_NAME: (value) => {
        if (value.match(NODE_NAME)) {
            return true;
        }
        return VALIDATOR_HINT.NODE_NAME;
    }
};

const cumulative = (value, divisor) => {
    let result = 0;
    if (value !== 0) {
        result = (value / divisor) * 100;
    }
    return `${result.toFixed(2)}%`;
};

export {
    regexes,
    mergeOptions,
    isIpAddressDefined,
    isIpv4MaskValid,
    isPasswordValid,
    isValidEmail,
    isIpValid,
    isValidName,
    isValidLoginDomain,
    isRangeValid,
    rangeValidation,
    validateSerialNumber,
    isIpv4MaskPrefixValid,
    isvalidNumber,
    validSiteId,
    isValidRetries,
    isValidTimeout,
    isValidJWTTimeout,
    isValidPort,
    isValidSiteName,
    isValidSiteLength,
    isValidLocalUserName,
    isValidHostName,
    isValidInBEpg,
    isValidDigit,
    isSpecial,
    isLowercase,
    isUppercase,
    operationalStages,
    cumulative,
    escapeIpwithMask,
    removeMaskFromIp,
    isIpPortValid,
    removeLeadTrailSpaces,
    isValidHostNamePort,
    VALIDATORS
};
