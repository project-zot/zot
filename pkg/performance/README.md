In performance_suite_test.go file, check init() function:
* define flag name for configuration file (line 24): **server.confi**

In command line, run the following command, where **server.config** is flag name and **server_config.json** is the server config file, in json format:
```
ginkgo -- -server.config="server_config.json" -measurement.config="measurement_config.json"
```

Creating images: In images directory, run the following command:
```
go run *.go
```

images: go run *.go