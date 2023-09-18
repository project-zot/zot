# Profiling in Zot

This project gives the user the posibility to debug and profile the runtime to find relevant data such as CPU intensive function calls. An in-depth article on profiling in Go can be found [here](https://go.dev/blog/pprof).

A call to http://localhost:8080/v2/_zot/pprof/ would list the following available profiles, wrapped in an HTML file, with count values prior to change due to the runtime:

```
Types of profiles available:
Count	Profile
95	allocs
0	block
0	cmdline
11	goroutine
95	heap
0	mutex
0	profile
13	threadcreate
0	trace
full goroutine stack dump
```

For example, the following can be used to gather the cpu profile for the amount of seconds specified as a query parameter, and then the results are stored in `cpu.prof` file:
```
curl -sK -v http://localhost:8080/v2/_zot/pprof/profile?seconds=30 > cpu.prof
```

Then, the user can use the `go tool pprof` to analyze the information generated previously in `cpu.prof`. The following command boots up an http server with a GUI and multiple charts that represent the data.
```
go tool pprof -http=:9090 cpu.prof
```
A flamegraph example would look like the following:

<img src="flamegraph.png" height="50%">