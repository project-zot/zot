In perf_suite_test.go file:

2. check init() function:
* define flag name for server configuration file: **server.config**
* define flag name for measurement configuration file: **measurement.config**

3. **server_config.json** file should contain: address, username, password, repo (string type) and tlsVerify (bool type). Also, in the measurement_config.json file the values can be changed.

4. In pkg/perf directory, run the following command, where **server.config** and **measurement.config** are the names of the flags and **server_config.json** and **measurement_config.json** are the config files, in json format:
```
ginkgo -- -server.config="server_config.json" -measurement.config="measurement_config.json"
```
