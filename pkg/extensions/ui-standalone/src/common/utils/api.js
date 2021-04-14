import axios from 'axios';
import {SESSION} from './session';
import {isEmpty} from 'lodash';
import {ENV} from '../../appEnv';
import {PREFIX, URL} from '../../constants';

const api = {

    // This method returns the generic request configuration for axios
    getRequestCfg: () => {
        let genericHeaders = {
            Accept: 'application/json',
            'Content-Type': 'application/json',
        };
        return {
            headers: genericHeaders,
        };
    },
    getPods(namespace) {
        let url = URL.getPodsUrl;
        if (namespace) {
            url = PREFIX.K8_API + 'namespaces/' + namespace + '/pods';
        }
        return axios.get(url, this.getRequestCfg());
    },
    getDeployment(namespace) {
        let url = URL.getDeploymentUrl;
        if (namespace) {
            url = PREFIX.K8_APPS_API + 'namespaces/' + namespace + '/deployments';
        }
        return axios.get(url, this.getRequestCfg());
    },
    getStatefulSet(namespace) {
        let url = URL.getStatefulSetUrl;
        if (namespace) {
            url = PREFIX.K8_APPS_API + 'namespaces/' + namespace + '/statefulsets';
        }
        return axios.get(url, this.getRequestCfg());
    },
    getServices(namespace) {
        let url = URL.getServicesUrl;
        if (namespace) {
            url = PREFIX.K8_API + 'namespaces/' + namespace + '/services';
        }
        return axios.get(url, this.getRequestCfg());
    },
    getReplicaSets(namespace) {
        let url = URL.getReplicaSetsUrl;
        if (namespace) {
            url = PREFIX.K8_APPS_API + 'namespaces/' + namespace + '/replicasets';
        }
        return axios.get(url, this.getRequestCfg());
    },
    getAuditLogs() {
        return axios.get(URL.getAuditLogsUrl, this.getRequestCfg());
    },
    getInBandStatus() {
        return axios.get(URL.getInBandUrl, this.getRequestCfg());
    },
    getManagementInBandEPGFault() {
        return axios.get(URL.getManagementInBandEPGFaultUrl, this.getRequestCfg());
    },
    deleteFirmware(uri, payload) {
        let cfg = this.getRequestCfg();
        return axios.delete(uri, {data: payload, cfg});
    },
    // Standalone
    pods(namespace) {
        let url = URL.pods;
        if (namespace) {
            url = url + '/' + namespace;
        }
        return axios.get(url, this.getRequestCfg());
    },
    replicasets(namespace) {
        let url = URL.replicasets;
        if (namespace) {
            url = PREFIX.K8_APPS_API + 'namespaces/' + namespace + '/replicasets';
        }
        return axios.get(url, this.getRequestCfg());
    },
    services(namespace) {
        let url = URL.services;
        if (namespace) {
            url = PREFIX.K8_API + 'namespaces/' + namespace + '/services';
        }
        return axios.get(url, this.getRequestCfg());
    },
    get(urli) {
        return axios.get(urli, this.getRequestCfg());
    },

    /**
     * This method creates the POST request with axios
     * If caller specifies the request configuration to be sent (@param cfg), it adds it to the request
     * If caller doesn't specfiy the request configuration, it adds the default config to the request
     * This allows caller to pass in any desired request configuration, based on the specifc need
     */
    post(urli, payload, cfg) {
        // generic post - generate config for request
        if (isEmpty(cfg)) {
            return axios.post(urli, payload, this.getRequestCfg());
        // custom post - use passed in config
        // TODO:: validate config object before sending request
        } else {
            return axios.post(urli, payload, cfg);
        }
    },
    put(urli, payload) {
        return axios.put(urli, payload, this.getRequestCfg());
    },
    delete(urli, payload) {
        let cfg = this.getRequestCfg();
        return axios.delete(urli, {data: payload, cfg});
    },
};

export default api;
