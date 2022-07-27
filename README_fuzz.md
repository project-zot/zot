# Fuzzing in Zot

This project makes use of native Go 1.18 fuzzing. An in-depth tutorial for fuzzing in Go can be found [here](https://go.dev/doc/fuzz/).
As language specifies, fuzz tests are included among unit-tests, inside the the same `*_test.go files`, in the packages they intend to fuzz. See [fuzzing for local storage](pkg/storage/local_test.go)

Zot doesn't store the test data for fuzzing in the same repo, nor it is added before fuzzing with `(*testing.F).Add` . Instead, it is stored in a separate repo called [test-data](https://github.com/project-zot/test-data).

To start fuzzing locally, one can use the Make target [fuzz-all](Makefile) .
**The default runtime for each fuzz test is 10s**, which can be overriden with the **fuzztime** variable
```
make fuzz-all fuzztime=20
```
By running this target, testdata for fuzzing gets downloaded from the previously mentioned repo and the fuzzing begins for every fuzz function that is found.