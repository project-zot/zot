workspace(name = "com_github_anuvu_zot")

go_version = "1.14.4"

go_os = "linux"

go_arch = "amd64"

load("@bazel_tools//tools/build_defs/repo:http.bzl", "http_archive")
load("@bazel_tools//tools/build_defs/repo:git.bzl", "git_repository")

go_rules_version = "v0.23.3"

http_archive(
    name = "io_bazel_rules_go",
    sha256 = "a8d6b1b354d371a646d2f7927319974e0f9e52f73a2452d2b3877118169eb6bb",
    urls = [
        "https://mirror.bazel.build/github.com/bazelbuild/rules_go/releases/download/{}/rules_go-{}.tar.gz".format(go_rules_version, go_rules_version),
        "https://github.com/bazelbuild/rules_go/releases/download/{}/rules_go-{}.tar.gz".format(go_rules_version, go_rules_version),
    ],
)

gazelle_version = "v0.21.0"

http_archive(
    name = "bazel_gazelle",
    sha256 = "bfd86b3cbe855d6c16c6fce60d76bd51f5c8dbc9cfcaef7a2bb5c1aafd0710e8",
    urls = ["https://github.com/bazelbuild/bazel-gazelle/releases/download/{}/bazel-gazelle-{}.tar.gz".format(gazelle_version, gazelle_version)],
)

buildtools_version = "0.25.1"

http_archive(
    name = "com_github_bazelbuild_buildtools",
    sha256 = "0a0920151acf18c51866331944d12db9023707a6861e78225366f5711efc845b",
    strip_prefix = "buildtools-{}".format(buildtools_version),
    urls = ["https://github.com/bazelbuild/buildtools/archive/{}.tar.gz".format(buildtools_version)],
)

git_repository(
    name = "com_github_atlassian_bazel_tools",
    commit = "6fbc36c639a8f376182bb0057dd557eb2440d4ed",
    remote = "https://github.com/atlassian/bazel-tools.git",
)

skylib_version = "1.0.2"

http_archive(
    name = "bazel_skylib",
    sha256 = "97e70364e9249702246c0e9444bccdc4b847bed1eb03c5a3ece4f83dfe6abc44",
    urls = [
        "https://mirror.bazel.build/github.com/bazelbuild/bazel-skylib/releases/download/{}/bazel-skylib-{}.tar.gz".format(skylib_version, skylib_version),
        "https://github.com/bazelbuild/bazel-skylib/releases/download/{}/bazel-skylib-{}.tar.gz".format(skylib_version, skylib_version),
    ],
)

load("@bazel_skylib//lib:versions.bzl", "versions")

versions.check(minimum_bazel_version = "0.26.1")

load("@io_bazel_rules_go//go:deps.bzl", "go_download_sdk", "go_register_toolchains", "go_rules_dependencies")

go_download_sdk(
    name = "go_sdk",
    goos = go_os,
    goarch = go_arch,
    version = go_version,
)

go_rules_dependencies()

go_register_toolchains(nogo = "@//:nogo")

load("@com_github_bazelbuild_buildtools//buildifier:deps.bzl", "buildifier_dependencies")
load("@com_github_atlassian_bazel_tools//buildozer:deps.bzl", "buildozer_dependencies")
load("@com_github_atlassian_bazel_tools//goimports:deps.bzl", "goimports_dependencies")
load("@com_github_atlassian_bazel_tools//golangcilint:deps.bzl", "golangcilint_dependencies")
load("@bazel_gazelle//:deps.bzl", "gazelle_dependencies", "go_repository")

gazelle_dependencies()

goimports_dependencies()

buildifier_dependencies()

buildozer_dependencies()

golangcilint_dependencies()

git_repository(
    name = "com_google_protobuf",
    commit = "09745575a923640154bcf307fba8aedff47f240a",
    remote = "https://github.com/protocolbuffers/protobuf",
    shallow_since = "1558721209 -0700",
)

load("@com_google_protobuf//:protobuf_deps.bzl", "protobuf_deps")

protobuf_deps()

go_repository(
    name = "co_honnef_go_tools",
    importpath = "honnef.co/go/tools",
    sum = "h1:3JgtbtFHMiCmsznwGVTUWbgGov+pVqnlf1dEJTNAXeM=",
    version = "v0.0.1-2019.2.3",
)

go_repository(
    name = "com_github_alecthomas_template",
    importpath = "github.com/alecthomas/template",
    sum = "h1:JYp7IbQjafoB+tBA3gMyHYHrpOtNuDiK/uB5uXxq5wM=",
    version = "v0.0.0-20190718012654-fb15b899a751",
)

go_repository(
    name = "com_github_alecthomas_units",
    importpath = "github.com/alecthomas/units",
    sum = "h1:qet1QNfXsQxTZqLG4oE62mJzwPIB8+Tee4RNCL9ulrY=",
    version = "v0.0.0-20151022065526-2efee857e7cf",
)

go_repository(
    name = "com_github_armon_consul_api",
    importpath = "github.com/armon/consul-api",
    sum = "h1:G1bPvciwNyF7IUmKXNt9Ak3m6u9DE1rF+RmtIkBpVdA=",
    version = "v0.0.0-20180202201655-eb2c6b5be1b6",
)

go_repository(
    name = "com_github_beorn7_perks",
    importpath = "github.com/beorn7/perks",
    sum = "h1:HWo1m869IqiPhD389kmkxeTalrjNbbJTC8LXupb+sl0=",
    version = "v1.0.0",
)

go_repository(
    name = "com_github_burntsushi_toml",
    importpath = "github.com/BurntSushi/toml",
    sum = "h1:WXkYYl6Yr3qBf1K79EBnL4mak0OimBfB0XUf9Vl28OQ=",
    version = "v0.3.1",
)

go_repository(
    name = "com_github_cespare_xxhash",
    importpath = "github.com/cespare/xxhash",
    sum = "h1:a6HrQnmkObjyL+Gs60czilIUGqrzKutQD6XZog3p+ko=",
    version = "v1.1.0",
)

go_repository(
    name = "com_github_chartmuseum_auth",
    importpath = "github.com/chartmuseum/auth",
    sum = "h1:CkCJPO/daho9iN9t6ztK4cJRjHkQoom5/n5ndAS3OyM=",
    version = "v0.4.0",
)

go_repository(
    name = "com_github_client9_misspell",
    importpath = "github.com/client9/misspell",
    sum = "h1:ta993UF76GwbvJcIo3Y68y/M3WxlpEHPWIGDkJYwzJI=",
    version = "v0.3.4",
)

go_repository(
    name = "com_github_coreos_bbolt",
    importpath = "github.com/coreos/bbolt",
    sum = "h1:wZwiHHUieZCquLkDL0B8UhzreNWsPHooDAG3q34zk0s=",
    version = "v1.3.2",
)

go_repository(
    name = "com_github_coreos_etcd",
    importpath = "github.com/coreos/etcd",
    sum = "h1:jFneRYjIvLMLhDLCzuTuU4rSJUjRplcJQ7pD7MnhC04=",
    version = "v3.3.10+incompatible",
)

go_repository(
    name = "com_github_coreos_go_semver",
    importpath = "github.com/coreos/go-semver",
    sum = "h1:wkHLiw0WNATZnSG7epLsujiMCgPAc9xhjJ4tgnAxmfM=",
    version = "v0.3.0",
)

go_repository(
    name = "com_github_coreos_go_systemd",
    importpath = "github.com/coreos/go-systemd",
    sum = "h1:Wf6HqHfScWJN9/ZjdUKyjop4mf3Qdd+1TvvltAvM3m8=",
    version = "v0.0.0-20190321100706-95778dfbb74e",
)

go_repository(
    name = "com_github_coreos_pkg",
    importpath = "github.com/coreos/pkg",
    sum = "h1:lBNOc5arjvs8E5mO2tbpBpLoyyu8B6e44T7hJy6potg=",
    version = "v0.0.0-20180928190104-399ea9e2e55f",
)

go_repository(
    name = "com_github_cpuguy83_go_md2man",
    importpath = "github.com/cpuguy83/go-md2man",
    sum = "h1:BSKMNlYxDvnunlTymqtgONjNnaRV1sTpcovwwjF22jk=",
    version = "v1.0.10",
)

go_repository(
    name = "com_github_davecgh_go_spew",
    importpath = "github.com/davecgh/go-spew",
    sum = "h1:vj9j/u1bqnvCEfJOwUhtlOARqs3+rkHYY13jYWTU97c=",
    version = "v1.1.1",
)

go_repository(
    name = "com_github_dgrijalva_jwt_go",
    importpath = "github.com/dgrijalva/jwt-go",
    sum = "h1:7qlOGliEKZXTDg6OTjfoBKDXWrumCAMpl/TFQ4/5kLM=",
    version = "v3.2.0+incompatible",
)

go_repository(
    name = "com_github_dgryski_go_sip13",
    importpath = "github.com/dgryski/go-sip13",
    sum = "h1:RMLoZVzv4GliuWafOuPuQDKSm1SJph7uCRnnS61JAn4=",
    version = "v0.0.0-20181026042036-e10d5fee7954",
)

go_repository(
    name = "com_github_fsnotify_fsnotify",
    importpath = "github.com/fsnotify/fsnotify",
    sum = "h1:IXs+QLmnXW2CcXuY+8Mzv/fWEsPGWxqefPtCP5CnV9I=",
    version = "v1.4.7",
)

go_repository(
    name = "com_github_ghodss_yaml",
    importpath = "github.com/ghodss/yaml",
    sum = "h1:wQHKEahhL6wmXdzwWG11gIVCkOv05bNOh+Rxn0yngAk=",
    version = "v1.0.0",
)

go_repository(
    name = "com_github_gin_contrib_sse",
    importpath = "github.com/gin-contrib/sse",
    sum = "h1:Y/yl/+YNO8GZSjAhjMsSuLt29uWRFHdHYUb5lYOV9qE=",
    version = "v0.1.0",
)

go_repository(
    name = "com_github_gin_gonic_gin",
    importpath = "github.com/gin-gonic/gin",
    sum = "h1:fi+bqFAx/oLK54somfCtEZs9HeH1LHVoEPUgARpTqyc=",
    version = "v1.5.0",
)

go_repository(
    name = "com_github_go_kit_kit",
    importpath = "github.com/go-kit/kit",
    sum = "h1:Wz+5lgoB0kkuqLEc6NVmwRknTKP6dTGbSqvhZtBI/j0=",
    version = "v0.8.0",
)

go_repository(
    name = "com_github_go_logfmt_logfmt",
    importpath = "github.com/go-logfmt/logfmt",
    sum = "h1:MP4Eh7ZCb31lleYCFuwm0oe4/YGak+5l1vA2NOE80nA=",
    version = "v0.4.0",
)

go_repository(
    name = "com_github_go_openapi_jsonpointer",
    importpath = "github.com/go-openapi/jsonpointer",
    sum = "h1:gihV7YNZK1iK6Tgwwsxo2rJbD1GTbdm72325Bq8FI3w=",
    version = "v0.19.3",
)

go_repository(
    name = "com_github_go_openapi_jsonreference",
    importpath = "github.com/go-openapi/jsonreference",
    sum = "h1:5cxNfTy0UVC3X8JL5ymxzyoUZmo8iZb+jeTWn7tUa8o=",
    version = "v0.19.3",
)

go_repository(
    name = "com_github_go_openapi_spec",
    importpath = "github.com/go-openapi/spec",
    sum = "h1:0XRyw8kguri6Yw4SxhsQA/atC88yqrk0+G4YhI2wabc=",
    version = "v0.19.3",
)

go_repository(
    name = "com_github_go_openapi_swag",
    importpath = "github.com/go-openapi/swag",
    sum = "h1:lTz6Ys4CmqqCQmZPBlbQENR1/GucA2bzYTE12Pw4tFY=",
    version = "v0.19.5",
)

go_repository(
    name = "com_github_go_stack_stack",
    importpath = "github.com/go-stack/stack",
    sum = "h1:5SgMzNM5HxrEjV0ww2lTmX6E2Izsfxas4+YHWRs3Lsk=",
    version = "v1.8.0",
)

go_repository(
    name = "com_github_gofrs_uuid",
    importpath = "github.com/gofrs/uuid",
    sum = "h1:y12jRkkFxsd7GpqdSZ+/KCs/fJbqpEXSGd4+jfEaewE=",
    version = "v3.2.0+incompatible",
)

go_repository(
    name = "com_github_gogo_protobuf",
    importpath = "github.com/gogo/protobuf",
    sum = "h1:DqDEcV5aeaTmdFBePNpYsp3FlcVH/2ISVVM9Qf8PSls=",
    version = "v1.3.1",
)

go_repository(
    name = "com_github_golang_glog",
    importpath = "github.com/golang/glog",
    sum = "h1:VKtxabqXZkF25pY9ekfRL6a582T4P37/31XEstQ5p58=",
    version = "v0.0.0-20160126235308-23def4e6c14b",
)

go_repository(
    name = "com_github_golang_groupcache",
    importpath = "github.com/golang/groupcache",
    sum = "h1:veQD95Isof8w9/WXiA+pa3tz3fJXkt5B7QaRBrM62gk=",
    version = "v0.0.0-20190129154638-5b532d6fd5ef",
)

go_repository(
    name = "com_github_golang_mock",
    importpath = "github.com/golang/mock",
    sum = "h1:28o5sBqPkBsMGnC6b4MvE2TzSr5/AT4c/1fLqVGIwlk=",
    version = "v1.2.0",
)

go_repository(
    name = "com_github_golang_protobuf",
    importpath = "github.com/golang/protobuf",
    sum = "h1:+Z5KGCizgyZCbGh1KZqA0fcLLkwbsjIzS4aV2v7wJX0=",
    version = "v1.4.2",
)

go_repository(
    name = "com_github_google_btree",
    importpath = "github.com/google/btree",
    sum = "h1:0udJVsspx3VBr5FwtLhQQtuAsVc79tTq0ocGIPAU6qo=",
    version = "v1.0.0",
)

go_repository(
    name = "com_github_google_go_cmp",
    importpath = "github.com/google/go-cmp",
    sum = "h1:/QaMHBdZ26BB3SSst0Iwl10Epc+xhTquomWX0oZEB6w=",
    version = "v0.5.0",
)

go_repository(
    name = "com_github_gopherjs_gopherjs",
    importpath = "github.com/gopherjs/gopherjs",
    sum = "h1:EGx4pi6eqNxGaHF6qqu48+N2wcFQ5qg5FXgOdqsJ5d8=",
    version = "v0.0.0-20181017120253-0766667cb4d1",
)

go_repository(
    name = "com_github_gorilla_websocket",
    importpath = "github.com/gorilla/websocket",
    sum = "h1:WDFjx/TMzVgy9VdMMQi2K2Emtwi2QcUQsztZ/zLaH/Q=",
    version = "v1.4.0",
)

go_repository(
    name = "com_github_grpc_ecosystem_go_grpc_middleware",
    importpath = "github.com/grpc-ecosystem/go-grpc-middleware",
    sum = "h1:z53tR0945TRRQO/fLEVPI6SMv7ZflF0TEaTAoU7tOzg=",
    version = "v1.0.1-0.20190118093823-f849b5445de4",
)

go_repository(
    name = "com_github_grpc_ecosystem_go_grpc_prometheus",
    importpath = "github.com/grpc-ecosystem/go-grpc-prometheus",
    sum = "h1:Ovs26xHkKqVztRpIrF/92BcuyuQ/YW4NSIpoGtfXNho=",
    version = "v1.2.0",
)

go_repository(
    name = "com_github_grpc_ecosystem_grpc_gateway",
    importpath = "github.com/grpc-ecosystem/grpc-gateway",
    sum = "h1:UImYN5qQ8tuGpGE16ZmjvcTtTw24zw1QAp/SlnNrZhI=",
    version = "v1.9.5",
)

go_repository(
    name = "com_github_hashicorp_hcl",
    importpath = "github.com/hashicorp/hcl",
    sum = "h1:0Anlzjpi4vEasTeNFn2mLJgTSwt0+6sfsiTG8qcWGx4=",
    version = "v1.0.0",
)

go_repository(
    name = "com_github_inconshreveable_mousetrap",
    importpath = "github.com/inconshreveable/mousetrap",
    sum = "h1:Z8tu5sraLXCXIcARxBp/8cbvlwVa7Z1NHg9XEKhtSvM=",
    version = "v1.0.0",
)

go_repository(
    name = "com_github_jonboulle_clockwork",
    importpath = "github.com/jonboulle/clockwork",
    sum = "h1:VKV+ZcuP6l3yW9doeqz6ziZGgcynBVQO+obU0+0hcPo=",
    version = "v0.1.0",
)

go_repository(
    name = "com_github_json_iterator_go",
    importpath = "github.com/json-iterator/go",
    sum = "h1:9yzud/Ht36ygwatGx56VwCZtlI/2AD15T1X2sjSuGns=",
    version = "v1.1.9",
)

go_repository(
    name = "com_github_jtolds_gls",
    importpath = "github.com/jtolds/gls",
    sum = "h1:xdiiI2gbIgH/gLH7ADydsJ1uDOEzR8yvV7C0MuV77Wo=",
    version = "v4.20.0+incompatible",
)

go_repository(
    name = "com_github_julienschmidt_httprouter",
    importpath = "github.com/julienschmidt/httprouter",
    sum = "h1:TDTW5Yz1mjftljbcKqRcrYhd4XeOoI98t+9HbQbYf7g=",
    version = "v1.2.0",
)

go_repository(
    name = "com_github_kisielk_errcheck",
    importpath = "github.com/kisielk/errcheck",
    sum = "h1:reN85Pxc5larApoH1keMBiu2GWtPqXQ1nc9gx+jOU+E=",
    version = "v1.2.0",
)

go_repository(
    name = "com_github_kisielk_gotool",
    importpath = "github.com/kisielk/gotool",
    sum = "h1:AV2c/EiW3KqPNT9ZKl07ehoAGi4C5/01Cfbblndcapg=",
    version = "v1.0.0",
)

go_repository(
    name = "com_github_konsorten_go_windows_terminal_sequences",
    importpath = "github.com/konsorten/go-windows-terminal-sequences",
    sum = "h1:CE8S1cTafDpPvMhIxNJKvHsGVBgn1xWYf1NbHQhywc8=",
    version = "v1.0.3",
)

go_repository(
    name = "com_github_kr_logfmt",
    importpath = "github.com/kr/logfmt",
    sum = "h1:T+h1c/A9Gawja4Y9mFVWj2vyii2bbUNDw3kt9VxK2EY=",
    version = "v0.0.0-20140226030751-b84e30acd515",
)

go_repository(
    name = "com_github_kr_pretty",
    importpath = "github.com/kr/pretty",
    sum = "h1:s5hAObm+yFO5uHYt5dYjxi2rXrsnmRpJx4OYvIWUaQs=",
    version = "v0.2.0",
)

go_repository(
    name = "com_github_kr_pty",
    importpath = "github.com/kr/pty",
    sum = "h1:hyz3dwM5QLc1Rfoz4FuWJQG5BN7tc6K1MndAUnGpQr4=",
    version = "v1.1.5",
)

go_repository(
    name = "com_github_kr_text",
    importpath = "github.com/kr/text",
    sum = "h1:5Nx0Ya0ZqY2ygV366QzturHI13Jq95ApcVaJBhpS+AY=",
    version = "v0.2.0",
)

go_repository(
    name = "com_github_magiconair_properties",
    importpath = "github.com/magiconair/properties",
    sum = "h1:ZC2Vc7/ZFkGmsVC9KvOjumD+G5lXy2RtTKyzRKO2BQ4=",
    version = "v1.8.1",
)

go_repository(
    name = "com_github_mailru_easyjson",
    importpath = "github.com/mailru/easyjson",
    sum = "h1:aizVhC/NAAcKWb+5QsU1iNOZb4Yws5UO2I+aIprQITM=",
    version = "v0.7.0",
)

go_repository(
    name = "com_github_mattn_go_isatty",
    importpath = "github.com/mattn/go-isatty",
    sum = "h1:wuysRhFDzyxgEmMf5xjvJ2M9dZoWAXNNr5LSBS7uHXY=",
    version = "v0.0.12",
)

go_repository(
    name = "com_github_matttproud_golang_protobuf_extensions",
    importpath = "github.com/matttproud/golang_protobuf_extensions",
    sum = "h1:4hp9jkHxhMHkqkrB3Ix0jegS5sx/RkqARlsWZ6pIwiU=",
    version = "v1.0.1",
)

go_repository(
    name = "com_github_mitchellh_go_homedir",
    importpath = "github.com/mitchellh/go-homedir",
    sum = "h1:lukF9ziXFxDFPkA1vsr5zpc1XuPDn/wFntq5mG+4E0Y=",
    version = "v1.1.0",
)

go_repository(
    name = "com_github_mitchellh_mapstructure",
    importpath = "github.com/mitchellh/mapstructure",
    sum = "h1:fmNYVwqnSfB9mZU6OS2O6GsXM+wcskZDuKQzvN1EDeE=",
    version = "v1.1.2",
)

go_repository(
    name = "com_github_modern_go_concurrent",
    importpath = "github.com/modern-go/concurrent",
    sum = "h1:TRLaZ9cD/w8PVh93nsPXa1VrQ6jlwL5oN8l14QlcNfg=",
    version = "v0.0.0-20180306012644-bacd9c7ef1dd",
)

go_repository(
    name = "com_github_modern_go_reflect2",
    importpath = "github.com/modern-go/reflect2",
    sum = "h1:9f412s+6RmYXLWZSEzVVgPGK7C2PphHj5RJrvfx9AWI=",
    version = "v1.0.1",
)

go_repository(
    name = "com_github_mwitkow_go_conntrack",
    importpath = "github.com/mwitkow/go-conntrack",
    sum = "h1:F9x/1yl3T2AeKLr2AMdilSD8+f9bvMnNN8VS5iDtovc=",
    version = "v0.0.0-20161129095857-cc309e4a2223",
)

go_repository(
    name = "com_github_oklog_ulid",
    importpath = "github.com/oklog/ulid",
    sum = "h1:EGfNDEx6MqHz8B3uNV6QAib1UR2Lm97sHi3ocA6ESJ4=",
    version = "v1.3.1",
)

go_repository(
    name = "com_github_oneofone_xxhash",
    importpath = "github.com/OneOfOne/xxhash",
    sum = "h1:KMrpdQIwFcEqXDklaen+P1axHaj9BSKzvpUUfnHldSE=",
    version = "v1.2.2",
)

go_repository(
    name = "com_github_opencontainers_distribution_spec",
    importpath = "github.com/opencontainers/distribution-spec",
    sum = "h1:xMzwhweo1gjvEo74mQjGTLau0TD3ACyTEC1310NbuSQ=",
    version = "v1.0.0-rc0",
)

go_repository(
    name = "com_github_opencontainers_go_digest",
    importpath = "github.com/opencontainers/go-digest",
    sum = "h1:WzifXhOVOEOuFYOJAW6aQqW0TooG2iki3E3Ii+WN7gQ=",
    version = "v1.0.0-rc1",
)

go_repository(
    name = "com_github_opencontainers_image_spec",
    importpath = "github.com/opencontainers/image-spec",
    sum = "h1:yN8BPXVwMBAm3Cuvh1L5XE8XpvYRMdsVLd82ILprhUU=",
    version = "v1.0.2-0.20190823105129-775207bd45b6",
)

go_repository(
    name = "com_github_pelletier_go_toml",
    importpath = "github.com/pelletier/go-toml",
    sum = "h1:T5zMGML61Wp+FlcbWjRDT7yAxhJNAiPPLOFECq181zc=",
    version = "v1.2.0",
)

go_repository(
    name = "com_github_pkg_errors",
    importpath = "github.com/pkg/errors",
    sum = "h1:FEBLx1zS214owpjy7qsBeixbURkuhQAwrK5UwLGTwt4=",
    version = "v0.9.1",
)

go_repository(
    name = "com_github_pmezard_go_difflib",
    importpath = "github.com/pmezard/go-difflib",
    sum = "h1:4DBwDE0NGyQoBHbLQYPwSUPoCMWR5BEzIk/f1lZbAQM=",
    version = "v1.0.0",
)

go_repository(
    name = "com_github_prometheus_client_golang",
    importpath = "github.com/prometheus/client_golang",
    sum = "h1:vrDKnkGzuGvhNAL56c7DBz29ZL+KxnoR0x7enabFceM=",
    version = "v1.0.0",
)

go_repository(
    name = "com_github_prometheus_client_model",
    importpath = "github.com/prometheus/client_model",
    sum = "h1:gQz4mCbXsO+nc9n1hCxHcGA3Zx3Eo+UHZoInFGUIXNM=",
    version = "v0.0.0-20190812154241-14fe0d1b01d4",
)

go_repository(
    name = "com_github_prometheus_common",
    importpath = "github.com/prometheus/common",
    sum = "h1:K0MGApIoQvMw27RTdJkPbr3JZ7DNbtxQNyi5STVM6Kw=",
    version = "v0.4.1",
)

go_repository(
    name = "com_github_prometheus_procfs",
    importpath = "github.com/prometheus/procfs",
    sum = "h1:6LJUbpNm42llc4HRCuvApCSWB/WfhuNo9K98Q9sNGfs=",
    version = "v0.0.2",
)

go_repository(
    name = "com_github_prometheus_tsdb",
    importpath = "github.com/prometheus/tsdb",
    sum = "h1:YZcsG11NqnK4czYLrWd9mpEuAJIHVQLwdrleYfszMAA=",
    version = "v0.7.1",
)

go_repository(
    name = "com_github_puerkitobio_purell",
    importpath = "github.com/PuerkitoBio/purell",
    sum = "h1:WEQqlqaGbrPkxLJWfBwQmfEAE1Z7ONdDLqrN38tNFfI=",
    version = "v1.1.1",
)

go_repository(
    name = "com_github_puerkitobio_urlesc",
    importpath = "github.com/PuerkitoBio/urlesc",
    sum = "h1:d+Bc7a5rLufV/sSk/8dngufqelfh6jnri85riMAaF/M=",
    version = "v0.0.0-20170810143723-de5bf2ad4578",
)

go_repository(
    name = "com_github_rogpeppe_fastuuid",
    importpath = "github.com/rogpeppe/fastuuid",
    sum = "h1:INyGLmTCMGFr6OVIb977ghJvABML2CMVjPoRfNDdYDo=",
    version = "v1.1.0",
)

go_repository(
    name = "com_github_rs_xid",
    importpath = "github.com/rs/xid",
    sum = "h1:mhH9Nq+C1fY2l1XIpgxIiUOfNpRBYH1kKcr+qfKgjRc=",
    version = "v1.2.1",
)

go_repository(
    name = "com_github_rs_zerolog",
    importpath = "github.com/rs/zerolog",
    sum = "h1:RMRHFw2+wF7LO0QqtELQwo8hqSmqISyCJeFeAAuWcRo=",
    version = "v1.17.2",
)

go_repository(
    name = "com_github_russross_blackfriday",
    importpath = "github.com/russross/blackfriday",
    sum = "h1:HyvC0ARfnZBqnXwABFeSZHpKvJHJJfPz81GNueLj0oo=",
    version = "v1.5.2",
)

go_repository(
    name = "com_github_sirupsen_logrus",
    importpath = "github.com/sirupsen/logrus",
    sum = "h1:UBcNElsrwanuuMsnGSlYmtmgbb23qDR5dG+6X6Oo89I=",
    version = "v1.6.0",
)

go_repository(
    name = "com_github_smartystreets_assertions",
    importpath = "github.com/smartystreets/assertions",
    sum = "h1:UVQPSSmc3qtTi+zPPkCXvZX9VvW/xT/NsRvKfwY81a8=",
    version = "v1.0.0",
)

go_repository(
    name = "com_github_smartystreets_goconvey",
    importpath = "github.com/smartystreets/goconvey",
    sum = "h1:fv0U8FUIMPNf1L9lnHLvLhgicrIVChEkdzIKYqbNC9s=",
    version = "v1.6.4",
)

go_repository(
    name = "com_github_soheilhy_cmux",
    importpath = "github.com/soheilhy/cmux",
    sum = "h1:0HKaf1o97UwFjHH9o5XsHUOF+tqmdA7KEzXLpiyaw0E=",
    version = "v0.1.4",
)

go_repository(
    name = "com_github_spaolacci_murmur3",
    importpath = "github.com/spaolacci/murmur3",
    sum = "h1:qLC7fQah7D6K1B0ujays3HV9gkFtllcxhzImRR7ArPQ=",
    version = "v0.0.0-20180118202830-f09979ecbc72",
)

go_repository(
    name = "com_github_spf13_afero",
    importpath = "github.com/spf13/afero",
    sum = "h1:5jhuqJyZCZf2JRofRvN/nIFgIWNzPa3/Vz8mYylgbWc=",
    version = "v1.2.2",
)

go_repository(
    name = "com_github_spf13_cast",
    importpath = "github.com/spf13/cast",
    sum = "h1:oget//CVOEoFewqQxwr0Ej5yjygnqGkvggSE/gB35Q8=",
    version = "v1.3.0",
)

go_repository(
    name = "com_github_spf13_cobra",
    importpath = "github.com/spf13/cobra",
    sum = "h1:f0B+LkLX6DtmRH1isoNA9VTtNUK9K8xYd28JNNfOv/s=",
    version = "v0.0.5",
)

go_repository(
    name = "com_github_spf13_jwalterweatherman",
    importpath = "github.com/spf13/jwalterweatherman",
    sum = "h1:XHEdyB+EcvlqZamSM4ZOMGlc93t6AcsBEu9Gc1vn7yk=",
    version = "v1.0.0",
)

go_repository(
    name = "com_github_spf13_pflag",
    importpath = "github.com/spf13/pflag",
    sum = "h1:iy+VFUOCP1a+8yFto/drg2CJ5u0yRoB7fZw3DKv/JXA=",
    version = "v1.0.5",
)

go_repository(
    name = "com_github_spf13_viper",
    importpath = "github.com/spf13/viper",
    sum = "h1:VPZzIkznI1YhVMRi6vNFLHSwhnhReBfgTxIPccpfdZk=",
    version = "v1.6.1",
)

go_repository(
    name = "com_github_stretchr_objx",
    importpath = "github.com/stretchr/objx",
    sum = "h1:Hbg2NidpLE8veEBkEZTL3CvlkUIVzuU9jDplZO54c48=",
    version = "v0.2.0",
)

go_repository(
    name = "com_github_stretchr_testify",
    importpath = "github.com/stretchr/testify",
    sum = "h1:hDPOHmpOpP40lSULcqw7IrRb/u7w6RpDC9399XyoNd0=",
    version = "v1.6.1",
)

go_repository(
    name = "com_github_swaggo_gin_swagger",
    importpath = "github.com/swaggo/gin-swagger",
    sum = "h1:YskZXEiv51fjOMTsXrOetAjrMDfFaXD79PEoQBOe2W0=",
    version = "v1.2.0",
)

go_repository(
    name = "com_github_swaggo_swag",
    importpath = "github.com/swaggo/swag",
    sum = "h1:N+uVPGP4H2hXoss2pt5dctoSUPKKRInr6qcTMOm0usI=",
    version = "v1.6.3",
)

go_repository(
    name = "com_github_tmc_grpc_websocket_proxy",
    importpath = "github.com/tmc/grpc-websocket-proxy",
    sum = "h1:LnC5Kc/wtumK+WB441p7ynQJzVuNRJiqddSIE3IlSEQ=",
    version = "v0.0.0-20190109142713-0ad062ec5ee5",
)

go_repository(
    name = "com_github_ugorji_go",
    importpath = "github.com/ugorji/go",
    sum = "h1:/68gy2h+1mWMrwZFeD1kQialdSzAb432dtpeJ42ovdo=",
    version = "v1.1.7",
)

go_repository(
    name = "com_github_ugorji_go_codec",
    importpath = "github.com/ugorji/go/codec",
    sum = "h1:2SvQaVZ1ouYrrKKwoSk2pzd4A9evlKJb9oTL+OaLUSs=",
    version = "v1.1.7",
)

go_repository(
    name = "com_github_urfave_cli",
    importpath = "github.com/urfave/cli",
    sum = "h1:u7tSpNPPswAFymm8IehJhy4uJMlUuU/GmqSkvJ1InXA=",
    version = "v1.22.4",
)

go_repository(
    name = "com_github_xiang90_probing",
    importpath = "github.com/xiang90/probing",
    sum = "h1:eY9dn8+vbi4tKz5Qo6v2eYzo7kUS51QINcR5jNpbZS8=",
    version = "v0.0.0-20190116061207-43a291ad63a2",
)

go_repository(
    name = "com_github_xordataexchange_crypt",
    importpath = "github.com/xordataexchange/crypt",
    sum = "h1:ESFSdwYZvkeru3RtdrYueztKhOBCSAAzS4Gf+k0tEow=",
    version = "v0.0.3-0.20170626215501-b2862e3d0a77",
)

go_repository(
    name = "com_github_zenazn_goji",
    importpath = "github.com/zenazn/goji",
    sum = "h1:RSQQAbXGArQ0dIDEq+PI6WqN6if+5KHu6x2Cx/GXLTQ=",
    version = "v0.9.0",
)

go_repository(
    name = "com_google_cloud_go",
    importpath = "cloud.google.com/go",
    sum = "h1:ROfEUZz+Gh5pa62DJWXSaonyu3StP6EA6lPEXPI6mCo=",
    version = "v0.38.0",
)

go_repository(
    name = "in_gopkg_alecthomas_kingpin_v2",
    importpath = "gopkg.in/alecthomas/kingpin.v2",
    sum = "h1:jMFz6MfLP0/4fUyZle81rXUoxOBFi19VUFKVDOQfozc=",
    version = "v2.2.6",
)

go_repository(
    name = "in_gopkg_check_v1",
    importpath = "gopkg.in/check.v1",
    sum = "h1:BLraFXnmrev5lT+xlilqcH8XK9/i0At2xKjWk4p6zsU=",
    version = "v1.0.0-20200227125254-8fa46927fb4f",
)

go_repository(
    name = "in_gopkg_go_playground_assert_v1",
    importpath = "gopkg.in/go-playground/assert.v1",
    sum = "h1:xoYuJVE7KT85PYWrN730RguIQO0ePzVRfFMXadIrXTM=",
    version = "v1.2.1",
)

go_repository(
    name = "in_gopkg_go_playground_validator_v8",
    importpath = "gopkg.in/go-playground/validator.v8",
    sum = "h1:lFB4DoMU6B626w8ny76MV7VX6W2VHct2GVOI3xgiMrQ=",
    version = "v8.18.2",
)

go_repository(
    name = "in_gopkg_resty_v1",
    importpath = "gopkg.in/resty.v1",
    sum = "h1:CuXP0Pjfw9rOuY6EP+UvtNvt5DSqHpIxILZKT/quCZI=",
    version = "v1.12.0",
)

go_repository(
    name = "in_gopkg_yaml_v2",
    importpath = "gopkg.in/yaml.v2",
    sum = "h1:obN1ZagJSUGI0Ek/LBmuj4SNLPfIny3KsKFopxRdj10=",
    version = "v2.2.8",
)

go_repository(
    name = "io_etcd_go_bbolt",
    importpath = "go.etcd.io/bbolt",
    sum = "h1:hi1bXHMVrlQh6WwxAy+qZCV/SYIlqo+Ushwdpa4tAKg=",
    version = "v1.3.4",
)

go_repository(
    name = "org_golang_google_appengine",
    importpath = "google.golang.org/appengine",
    sum = "h1:KxkO13IPW4Lslp2bz+KHP2E3gtFlrIGNThxkZQ3g+4c=",
    version = "v1.5.0",
)

go_repository(
    name = "org_golang_google_genproto",
    importpath = "google.golang.org/genproto",
    sum = "h1:+kGHl1aib/qcwaRi1CbqBZ1rk19r85MNUf8HaBghugY=",
    version = "v0.0.0-20200526211855-cb27e3aa2013",
)

go_repository(
    name = "org_golang_google_grpc",
    importpath = "google.golang.org/grpc",
    sum = "h1:bO/TA4OxCOummhSf10siHuG7vJOiwh7SpRpFZDkOgl4=",
    version = "v1.28.0",
)

go_repository(
    name = "org_golang_x_crypto",
    importpath = "golang.org/x/crypto",
    sum = "h1:vEg9joUBmeBcK9iSJftGNf3coIG4HqZElCPehJsfAYM=",
    version = "v0.0.0-20200604202706-70a84ac30bf9",
)

go_repository(
    name = "org_golang_x_lint",
    importpath = "golang.org/x/lint",
    sum = "h1:5hukYrvBGR8/eNkX5mdUezrA6JiaEZDtJb9Ei+1LlBs=",
    version = "v0.0.0-20190930215403-16217165b5de",
)

go_repository(
    name = "org_golang_x_net",
    importpath = "golang.org/x/net",
    sum = "h1:pNX+40auqi2JqRfOP1akLGtYcn15TUbkhwuCO3foqqM=",
    version = "v0.0.0-20200602114024-627f9648deb9",
)

go_repository(
    name = "org_golang_x_oauth2",
    importpath = "golang.org/x/oauth2",
    sum = "h1:TzXSXBo42m9gQenoE3b9BGiEpg5IG2JkU5FkPIawgtw=",
    version = "v0.0.0-20200107190931-bf48bf16ab8d",
)

go_repository(
    name = "org_golang_x_sync",
    importpath = "golang.org/x/sync",
    sum = "h1:vcxGaoTs7kV8m5Np9uUNQin4BrLOthgV7252N8V+FwY=",
    version = "v0.0.0-20190911185100-cd5d95a43a6e",
)

go_repository(
    name = "org_golang_x_sys",
    importpath = "golang.org/x/sys",
    sum = "h1:ogLJMz+qpzav7lGMh10LMvAkM/fAoGlaiiHYiFYdm80=",
    version = "v0.0.0-20200615200032-f1bc736245b1",
)

go_repository(
    name = "org_golang_x_text",
    importpath = "golang.org/x/text",
    sum = "h1:tW2bmiBqwgJj/UpqtC8EpXEZVYOwU0yG4iWbprSVAcs=",
    version = "v0.3.2",
)

go_repository(
    name = "org_golang_x_time",
    importpath = "golang.org/x/time",
    sum = "h1:/5xXl8Y5W96D+TtHSlonuFqGHIWVuyCkGJLwGh9JJFs=",
    version = "v0.0.0-20191024005414-555d28b269f0",
)

go_repository(
    name = "org_golang_x_tools",
    importpath = "golang.org/x/tools",
    sum = "h1:a/Fd23DJvg1CaeDH0dYHahE+hCI0v9rFgxSNIThoUcM=",
    version = "v0.0.0-20200210192313-1ace956b0e17",
)

go_repository(
    name = "org_uber_go_atomic",
    importpath = "go.uber.org/atomic",
    sum = "h1:rsqfU5vBkVknbhUGbAUwQKR2H4ItV8tjJ+6kJX4cxHM=",
    version = "v1.5.1",
)

go_repository(
    name = "org_uber_go_multierr",
    importpath = "go.uber.org/multierr",
    sum = "h1:f3WCSC2KzAcBXGATIxAB1E2XuCpNU255wNKZ505qi3E=",
    version = "v1.4.0",
)

go_repository(
    name = "org_uber_go_zap",
    importpath = "go.uber.org/zap",
    sum = "h1:nR6NoDBgAf67s68NhaXbsojM+2gxp3S1hWkHDl27pVU=",
    version = "v1.13.0",
)

go_repository(
    name = "com_github_gorilla_mux",
    importpath = "github.com/gorilla/mux",
    sum = "h1:VuZ8uybHlWmqV03+zRzdwKL4tUnIp1MAQtp1mIFE1bc=",
    version = "v1.7.4",
)

go_repository(
    name = "com_github_kylebanks_depth",
    importpath = "github.com/KyleBanks/depth",
    sum = "h1:5h8fQADFrWtarTdtDudMmGsC7GPbOAu6RVB3ffsVFHc=",
    version = "v1.2.1",
)

go_repository(
    name = "com_github_swaggo_files",
    importpath = "github.com/swaggo/files",
    sum = "h1:PyYN9JH5jY9j6av01SpfRMb+1DWg/i3MbGOKPxJ2wjM=",
    version = "v0.0.0-20190704085106-630677cd5c14",
)

go_repository(
    name = "com_github_swaggo_http_swagger",
    importpath = "github.com/swaggo/http-swagger",
    sum = "h1:m5sYJ43teIUlESuKRFQRRm7kqi6ExiYwVKfoXNuRgHU=",
    version = "v0.0.0-20190614090009-c2865af9083e",
)

go_repository(
    name = "com_github_go_chi_chi",
    importpath = "github.com/go-chi/chi",
    sum = "h1:maB6vn6FqCxrpz4FqWdh4+lwpyZIQS7YEAUcHlgXVRs=",
    version = "v4.0.2+incompatible",
)

go_repository(
    name = "org_golang_x_xerrors",
    importpath = "golang.org/x/xerrors",
    sum = "h1:E7g+9GITq07hpfrRu66IVDexMakfv52eLZ2CXBWiKr4=",
    version = "v0.0.0-20191204190536-9bdfabe68543",
)

go_repository(
    name = "com_github_boombuler_barcode",
    importpath = "github.com/boombuler/barcode",
    sum = "h1:biVzkmvwrH8WK8raXaxBx6fRVTlJILwEwQGL1I/ByEI=",
    version = "v1.0.1-0.20190219062509-6c824513bacc",
)

go_repository(
    name = "com_github_docopt_docopt_go",
    importpath = "github.com/docopt/docopt-go",
    sum = "h1:bWDMxwH3px2JBh6AyO7hdCn/PkvCZXii8TGj7sbtEbQ=",
    version = "v0.0.0-20180111231733-ee0de3bc6815",
)

go_repository(
    name = "com_github_geertjohan_yubigo",
    importpath = "github.com/GeertJohan/yubigo",
    sum = "h1:KA/G9j1p6mBmMihAZwmpnS6t8WsToyVlvF2v5VgJIcY=",
    version = "v0.0.0-20190829090426-2d4089dc8789",
)

go_repository(
    name = "com_github_glauth_glauth",
    importpath = "github.com/glauth/glauth",
    sum = "h1:2Rl5vTPWlchM4P+VCUtHbD7U3wFcoLYZiTwYad2QCOM=",
    version = "v1.1.1",
)

go_repository(
    name = "com_github_jtblin_go_ldap_client",
    importpath = "github.com/jtblin/go-ldap-client",
    sum = "h1:XDpFOMOZq0u0Ar4F0p/wklqQXp/AMV1pTF5T5bDoUfQ=",
    version = "v0.0.0-20170223121919-b73f66626b33",
)

go_repository(
    name = "com_github_mitchellh_mapstructure",
    importpath = "github.com/mitchellh/mapstructure",
    sum = "h1:fmNYVwqnSfB9mZU6OS2O6GsXM+wcskZDuKQzvN1EDeE=",
    version = "v1.1.2",
)

go_repository(
    name = "com_github_nmcclain_asn1_ber",
    importpath = "github.com/nmcclain/asn1-ber",
    sum = "h1:D9EvfGQvlkKaDr2CRKN++7HbSXbefUNDrPq60T+g24s=",
    version = "v0.0.0-20170104154839-2661553a0484",
)

go_repository(
    name = "com_github_nmcclain_ldap",
    importpath = "github.com/nmcclain/ldap",
    sum = "h1:NNis9uuNpG5h97Dvxxo53Scg02qBg+3Nfabg6zjFGu8=",
    version = "v0.0.0-20191021200707-3b3b69a7e9e3",
)

go_repository(
    name = "com_github_op_go_logging",
    importpath = "github.com/op/go-logging",
    sum = "h1:lDH9UUVJtmYCjyT0CI4q8xvlXPxeZ0gYCVvWbmPlp88=",
    version = "v0.0.0-20160315200505-970db520ece7",
)

go_repository(
    name = "com_github_opencontainers_go_digest",
    importpath = "github.com/opencontainers/go-digest",
    sum = "h1:WzifXhOVOEOuFYOJAW6aQqW0TooG2iki3E3Ii+WN7gQ=",
    version = "v1.0.0-rc1",
)

go_repository(
    name = "com_github_phayes_freeport",
    importpath = "github.com/phayes/freeport",
    sum = "h1:JhzVVoYvbOACxoUmOs6V/G4D5nPVUW73rKvXxP4XUJc=",
    version = "v0.0.0-20180830031419-95f893ade6f2",
)

go_repository(
    name = "com_github_pquerna_otp",
    importpath = "github.com/pquerna/otp",
    sum = "h1:/A3+Jn+cagqayeR3iHs/L62m5ue7710D35zl1zJ1kok=",
    version = "v1.2.0",
)

go_repository(
    name = "com_github_samuel_go_ldap",
    importpath = "github.com/samuel/go-ldap",
    sum = "h1:1iey3/nAwh5WYP9DGAH6vZGyBhCbRZ0fkX33LO138Fg=",
    version = "v0.0.0-20150819063227-09b1a56d2755",
)

go_repository(
    name = "com_github_vjeantet_ldapserver",
    importpath = "github.com/vjeantet/ldapserver",
    sum = "h1:VWE8ZC9ER1YIfx0V0QgZGdG4UB/nGeaSmKxesfVuheo=",
    version = "v0.0.0-20170919170217-479fece7c5f1",
)

go_repository(
    name = "in_gopkg_amz_v1",
    importpath = "gopkg.in/amz.v1",
    sum = "h1:FMrsB0OTjHsPDA1NM7AhRmmZzkBPu3iGdxK/5MFfBmk=",
    version = "v1.0.0-20150111123259-ad23e96a31d2",
)

go_repository(
    name = "in_gopkg_asn1_ber_v1",
    importpath = "gopkg.in/asn1-ber.v1",
    sum = "h1:TxyelI5cVkbREznMhfzycHdkp5cLA7DpE+GKjSslYhM=",
    version = "v1.0.0-20181015200546-f715ec2f112d",
)

go_repository(
    name = "in_gopkg_ldap_v2",
    importpath = "gopkg.in/ldap.v2",
    sum = "h1:wiu0okdNfjlBzg6UWvd1Hn8Y+Ux17/u/4nlk4CQr6tU=",
    version = "v2.5.1",
)

go_repository(
    name = "com_github_getlantern_deepcopy",
    importpath = "github.com/getlantern/deepcopy",
    sum = "h1:yU/FENpkHYISWsQrbr3pcZOBj0EuRjPzNc1+dTCLu44=",
    version = "v0.0.0-20160317154340-7f45deb8130a",
)

go_repository(
    name = "com_github_gorilla_handlers",
    importpath = "github.com/gorilla/handlers",
    sum = "h1:0QniY0USkHQ1RGCLfKxeNHK9bkDHGRYGNDFBCS+YARg=",
    version = "v1.4.2",
)

go_repository(
    name = "com_github_gin_contrib_gzip",
    importpath = "github.com/gin-contrib/gzip",
    sum = "h1:ezvKOL6jH+jlzdHNE4h9h8q8uMpDQjyl0NN0Jd7jozc=",
    version = "v0.0.1",
)

go_repository(
    name = "com_github_go_asn1_ber_asn1_ber",
    importpath = "github.com/go-asn1-ber/asn1-ber",
    sum = "h1:gvPdv/Hr++TRFCl0UbPFHC54P9N9jgsRPnmnr419Uck=",
    version = "v1.3.1",
)

go_repository(
    name = "com_github_go_ldap_ldap_v3",
    importpath = "github.com/go-ldap/ldap/v3",
    sum = "h1:RIgdpHXJpsUqUK5WXwKyVsESrGFqo5BRWPk3RR4/ogQ=",
    version = "v3.1.3",
)

go_repository(
    name = "com_github_google_gofuzz",
    importpath = "github.com/google/gofuzz",
    sum = "h1:A8PeW59pxE9IoFRqBp37U+mSNaQoZ46F1f0f863XSXw=",
    version = "v1.0.0",
)

go_repository(
    name = "com_github_subosito_gotenv",
    importpath = "github.com/subosito/gotenv",
    sum = "h1:Slr1R9HxAlEKefgq5jn9U+DnETlIUa6HfgEzj0g5d7s=",
    version = "v1.2.0",
)

go_repository(
    name = "in_gopkg_ini_v1",
    importpath = "gopkg.in/ini.v1",
    sum = "h1:AQvPpx3LzTDM0AjnIRlVFwFFGC+npRopjZxLJj6gdno=",
    version = "v1.51.0",
)

go_repository(
    name = "com_github_boltdb_bolt",
    importpath = "github.com/boltdb/bolt",
    sum = "h1:JQmyP4ZBrce+ZQu0dY660FMfatumYDLun9hBCUVIkF4=",
    version = "v1.3.1",
)

go_repository(
    name = "com_github_etcd_io_bbolt",
    importpath = "github.com/etcd-io/bbolt",
    sum = "h1:gSJmxrs37LgTqR/oyJBWok6k6SvXEUerFTbltIhXkBM=",
    version = "v1.3.3",
)

go_repository(
    name = "com_github_apex_log",
    importpath = "github.com/apex/log",
    sum = "h1:jYWeNt9kWJOf1ifht8UjsCQ00eiPnFrUzCBCiiJMw/g=",
    version = "v1.4.0",
)

go_repository(
    name = "com_github_aphistic_golf",
    importpath = "github.com/aphistic/golf",
    sum = "h1:2KLQMJ8msqoPHIPDufkxVcoTtcmE5+1sL9950m4R9Pk=",
    version = "v0.0.0-20180712155816-02c07f170c5a",
)

go_repository(
    name = "com_github_aphistic_sweet",
    importpath = "github.com/aphistic/sweet",
    sum = "h1:I4z+fAUqvKfvZV/CHi5dV0QuwbmIvYYFDjG0Ss5QpAs=",
    version = "v0.2.0",
)

go_repository(
    name = "com_github_aws_aws_sdk_go",
    importpath = "github.com/aws/aws-sdk-go",
    sum = "h1:MXnqY6SlWySaZAqNnXThOvjRFdiiOuKtC6i7baFdNdU=",
    version = "v1.27.1",
)

go_repository(
    name = "com_github_aybabtme_rgbterm",
    importpath = "github.com/aybabtme/rgbterm",
    sum = "h1:WWB576BN5zNSZc/M9d/10pqEx5VHNhaQ/yOVAkmj5Yo=",
    version = "v0.0.0-20170906152045-cc83f3b3ce59",
)

go_repository(
    name = "com_github_cpuguy83_go_md2man_v2",
    importpath = "github.com/cpuguy83/go-md2man/v2",
    sum = "h1:EoUDS0afbrsXAZ9YQ9jdu/mZ2sXgT1/2yyNng4PGlyM=",
    version = "v2.0.0",
)

go_repository(
    name = "com_github_creack_pty",
    importpath = "github.com/creack/pty",
    sum = "h1:uDmaGzcdjhF4i/plgjmEsriH11Y0o7RKapEf/LDaM3w=",
    version = "v1.1.9",
)

go_repository(
    name = "com_github_cyphar_filepath_securejoin",
    importpath = "github.com/cyphar/filepath-securejoin",
    sum = "h1:jCwT2GTP+PY5nBz3c/YL5PAIbusElVrPujOBSCj8xRg=",
    version = "v0.2.2",
)

go_repository(
    name = "com_github_docker_go_units",
    importpath = "github.com/docker/go-units",
    sum = "h1:3uh0PgVws3nIA0Q+MwDC8yjEPf9zjRfZZWXZYDct3Tw=",
    version = "v0.4.0",
)

go_repository(
    name = "com_github_fatih_color",
    importpath = "github.com/fatih/color",
    sum = "h1:8xPHl4/q1VyqGIPif1F+1V3Y3lSmrq01EabUW3CoW5s=",
    version = "v1.9.0",
)

go_repository(
    name = "com_github_google_uuid",
    importpath = "github.com/google/uuid",
    sum = "h1:Gkbcsh/GbpXz7lPftLA3P6TYMwjCLYm83jiFQZF/3gY=",
    version = "v1.1.1",
)

go_repository(
    name = "com_github_hpcloud_tail",
    importpath = "github.com/hpcloud/tail",
    sum = "h1:nfCOvKYfkgYP8hkirhJocXT2+zOD8yUNjXaWfTlyFKI=",
    version = "v1.0.0",
)

go_repository(
    name = "com_github_jmespath_go_jmespath",
    importpath = "github.com/jmespath/go-jmespath",
    sum = "h1:pmfjZENx5imkbgOkpRUYLnmbU7UEFbjtDA2hxJ1ichM=",
    version = "v0.0.0-20180206201540-c2b33e8439af",
)

go_repository(
    name = "com_github_jpillora_backoff",
    importpath = "github.com/jpillora/backoff",
    sum = "h1:K//n/AqR5HjG3qxbrBCL4vJPW0MVFSs9CPK1OOJdRME=",
    version = "v0.0.0-20180909062703-3050d21c67d7",
)

go_repository(
    name = "com_github_klauspost_compress",
    importpath = "github.com/klauspost/compress",
    sum = "h1:pPRt1Z78crspaHISkpSSHjDlx+Tt9suHe519dsI0vF4=",
    version = "v1.10.9",
)

go_repository(
    name = "com_github_klauspost_cpuid",
    importpath = "github.com/klauspost/cpuid",
    sum = "h1:vJi+O/nMdFt0vqm8NZBI6wzALWdA2X+egi0ogNyrC/w=",
    version = "v1.2.1",
)

go_repository(
    name = "com_github_klauspost_pgzip",
    importpath = "github.com/klauspost/pgzip",
    sum = "h1:TQ7CNpYKovDOmqzRHKxJh0BeaBI7UdQZYc6p7pMQh1A=",
    version = "v1.2.4",
)

go_repository(
    name = "com_github_mattn_go_colorable",
    importpath = "github.com/mattn/go-colorable",
    sum = "h1:6Su7aK7lXmJ/U79bYtBjLNaha4Fs1Rg9plHpcH+vvnE=",
    version = "v0.1.6",
)

go_repository(
    name = "com_github_mgutz_ansi",
    importpath = "github.com/mgutz/ansi",
    sum = "h1:j7+1HpAFS1zy5+Q4qx1fWh90gTKwiN4QCGoY9TWyyO4=",
    version = "v0.0.0-20170206155736-9520e82c474b",
)

go_repository(
    name = "com_github_mohae_deepcopy",
    importpath = "github.com/mohae/deepcopy",
    sum = "h1:RWengNIwukTxcDr9M+97sNutRR1RKhG96O6jWumTTnw=",
    version = "v0.0.0-20170929034955-c48cc78d4826",
)

go_repository(
    name = "com_github_onsi_ginkgo",
    importpath = "github.com/onsi/ginkgo",
    sum = "h1:q/mM8GF/n0shIN8SaAZ0V+jnLPzen6WIVZdiwrRlMlo=",
    version = "v1.10.1",
)

go_repository(
    name = "com_github_onsi_gomega",
    importpath = "github.com/onsi/gomega",
    sum = "h1:XPnZz8VVBHjVsy1vzJmRwIcSwiUO+JFfrv/xGiigmME=",
    version = "v1.7.0",
)

go_repository(
    name = "com_github_opencontainers_runtime_spec",
    importpath = "github.com/opencontainers/runtime-spec",
    sum = "h1:UfAcuLBJB9Coz72x1hgl8O5RVzTdNiaglX6v2DM6FI0=",
    version = "v1.0.2",
)

go_repository(
    name = "com_github_rootless_containers_proto",
    importpath = "github.com/rootless-containers/proto",
    sum = "h1:gS1JOMEtk1YDYHCzBAf/url+olMJbac7MTrgSeP6zh4=",
    version = "v0.1.0",
)

go_repository(
    name = "com_github_russross_blackfriday_v2",
    importpath = "github.com/russross/blackfriday/v2",
    sum = "h1:lPqVAte+HuHNfhJ/0LC98ESWRz8afy9tM/0RK8m9o+Q=",
    version = "v2.0.1",
)

go_repository(
    name = "com_github_sergi_go_diff",
    importpath = "github.com/sergi/go-diff",
    sum = "h1:we8PVUC3FE2uYfodKH/nBHMSetSfHDR6scGdBi+erh0=",
    version = "v1.1.0",
)

go_repository(
    name = "com_github_shurcool_sanitized_anchor_name",
    importpath = "github.com/shurcooL/sanitized_anchor_name",
    sum = "h1:PdmoCO6wvbs+7yrJyMORt4/BmY5IYyJwS/kOiWx8mHo=",
    version = "v1.0.0",
)

go_repository(
    name = "com_github_smartystreets_go_aws_auth",
    importpath = "github.com/smartystreets/go-aws-auth",
    sum = "h1:hp2CYQUINdZMHdvTdXtPOY2ainKl4IoMcpAXEf2xj3Q=",
    version = "v0.0.0-20180515143844-0c1422d1fdb9",
)

go_repository(
    name = "com_github_smartystreets_gunit",
    importpath = "github.com/smartystreets/gunit",
    sum = "h1:RyPDUFcJbvtXlhJPk7v+wnxZRY2EUokhEYl2EJOPToI=",
    version = "v1.0.0",
)

go_repository(
    name = "com_github_tj_assert",
    importpath = "github.com/tj/assert",
    sum = "h1:Df/BlaZ20mq6kuai7f5z2TvPFiwC3xaWJSDQNiIS3Rk=",
    version = "v0.0.3",
)

go_repository(
    name = "com_github_tj_go_elastic",
    importpath = "github.com/tj/go-elastic",
    sum = "h1:eGaGNxrtoZf/mBURsnNQKDR7u50Klgcf2eFDQEnc8Bc=",
    version = "v0.0.0-20171221160941-36157cbbebc2",
)

go_repository(
    name = "com_github_tj_go_kinesis",
    importpath = "github.com/tj/go-kinesis",
    sum = "h1:m74UWYy+HBs+jMFR9mdZU6shPewugMyH5+GV6LNgW8w=",
    version = "v0.0.0-20171128231115-08b17f58cb1b",
)

go_repository(
    name = "com_github_tj_go_spin",
    importpath = "github.com/tj/go-spin",
    sum = "h1:lhdWZsvImxvZ3q1C5OIB7d72DuOwP4O2NdBg9PyzNds=",
    version = "v1.1.0",
)

go_repository(
    name = "com_github_vbatts_go_mtree",
    importpath = "github.com/vbatts/go-mtree",
    sum = "h1:dM+5XZdqH0j9CSZeerhoN/tAySdwnmevaZHO1XGW2Vc=",
    version = "v0.5.0",
)

go_repository(
    name = "in_gopkg_fsnotify_v1",
    importpath = "gopkg.in/fsnotify.v1",
    sum = "h1:xOHLXZwVvI9hhs+cLKq5+I5onOuwQLhQwiu63xxlHs4=",
    version = "v1.4.7",
)

go_repository(
    name = "in_gopkg_tomb_v1",
    importpath = "gopkg.in/tomb.v1",
    sum = "h1:uRGJdciOHaEIrze2W8Q3AKkepLTh2hOroT7a+7czfdQ=",
    version = "v1.0.0-20141024135613-dd632973f1e7",
)

go_repository(
    name = "com_github_alcortesm_tgz",
    importpath = "github.com/alcortesm/tgz",
    sum = "h1:uSoVVbwJiQipAclBbw+8quDsfcvFjOpI5iCf4p/cqCs=",
    version = "v0.0.0-20161220082320-9c5fe88206d7",
)

go_repository(
    name = "com_github_anmitsu_go_shlex",
    importpath = "github.com/anmitsu/go-shlex",
    sum = "h1:kFOfPq6dUM1hTo4JG6LR5AXSUEsOjtdm0kw0FtQtMJA=",
    version = "v0.0.0-20161002113705-648efa622239",
)

go_repository(
    name = "com_github_aquasecurity_fanal",
    importpath = "github.com/aquasecurity/fanal",
    replace = "github.com/anuvu/fanal",
    sum = "h1:ft16YDnT+8Z5tuc7WvP5X1iq5WdjHaqJF+uGXBPQeKc=",
    version = "v0.0.0-20200623180831-a648790ef38e",
)

go_repository(
    name = "com_github_aquasecurity_go_dep_parser",
    importpath = "github.com/aquasecurity/go-dep-parser",
    sum = "h1:55Ulc/gvfWm4ylhVaR7MxOwujRjA6et7KhmUbSgUFf4=",
    version = "v0.0.0-20190819075924-ea223f0ef24b",
)

go_repository(
    name = "com_github_aquasecurity_testdocker",
    importpath = "github.com/aquasecurity/testdocker",
    sum = "h1:hsw7PpiymXP64evn/K7gsj3hWzMqLrdoeE6JkqDocVg=",
    version = "v0.0.0-20200426142840-5f05bce6f12a",
)

go_repository(
    name = "com_github_aquasecurity_trivy",
    build_extra_args = ["-exclude=vendor"],
    build_file_proto_mode = "disable",
    importpath = "github.com/aquasecurity/trivy",
    replace = "github.com/anuvu/trivy",
    sum = "h1:dMWcl9ev/Wpw6Szhxuknluln6zFlQ8sSMOlCT16D9xw=",
    version = "v0.9.2-0.20200624055514-7fa927d7ca1d",
)

go_repository(
    name = "com_github_aquasecurity_trivy_db",
    importpath = "github.com/aquasecurity/trivy-db",
    replace = "github.com/anuvu/trivy-db",
    sum = "h1:A37WALDUn+HtuNI/81p+cUzHe/8IE7m9zxVzsXP/b4E=",
    version = "v0.0.0-20200623200932-d185809a68f7",
)

go_repository(
    name = "com_github_aquasecurity_vuln_list_update",
    importpath = "github.com/aquasecurity/vuln-list-update",
    sum = "h1:xbdUfr2KE4THsFx9CFWtWpU91lF+YhgP46moV94nYTA=",
    version = "v0.0.0-20191016075347-3d158c2bf9a2",
)

go_repository(
    name = "com_github_araddon_dateparse",
    importpath = "github.com/araddon/dateparse",
    sum = "h1:ukTLOeMC0aVxbJWVg6hOsVJ0VPIo8w++PbNsze/pqF8=",
    version = "v0.0.0-20190426192744-0d74ffceef83",
)

go_repository(
    name = "com_github_armon_go_socks5",
    importpath = "github.com/armon/go-socks5",
    sum = "h1:0CwZNZbxp69SHPdPJAN/hZIm0C4OItdklCFmMRWYpio=",
    version = "v0.0.0-20160902184237-e75332964ef5",
)

go_repository(
    name = "com_github_azure_azure_sdk_for_go",
    importpath = "github.com/Azure/azure-sdk-for-go",
    sum = "h1:3D2O4g8AwDwyWkM1HpMFVux/ccQJmGJHXsE004Wsu1Q=",
    version = "v38.0.0+incompatible",
)

go_repository(
    name = "com_github_azure_go_ansiterm",
    importpath = "github.com/Azure/go-ansiterm",
    sum = "h1:w+iIsaOQNcT7OZ575w+acHgRric5iCyQh+xv+KJ4HB8=",
    version = "v0.0.0-20170929234023-d6e3b3328b78",
)

go_repository(
    name = "com_github_azure_go_autorest_autorest",
    importpath = "github.com/Azure/go-autorest/autorest",
    sum = "h1:OZEIaBbMdUE/Js+BQKlpO81XlISgipr6yDJ+PSwsgi4=",
    version = "v0.9.3",
)

go_repository(
    name = "com_github_azure_go_autorest_autorest_adal",
    importpath = "github.com/Azure/go-autorest/autorest/adal",
    sum = "h1:pZdL8o72rK+avFWl+p9nE8RWi1JInZrWJYlnpfXJwHk=",
    version = "v0.8.1",
)

go_repository(
    name = "com_github_azure_go_autorest_autorest_date",
    importpath = "github.com/Azure/go-autorest/autorest/date",
    sum = "h1:yW+Zlqf26583pE43KhfnhFcdmSWlm5Ew6bxipnr/tbM=",
    version = "v0.2.0",
)

go_repository(
    name = "com_github_azure_go_autorest_autorest_mocks",
    importpath = "github.com/Azure/go-autorest/autorest/mocks",
    sum = "h1:qJumjCaCudz+OcqE9/XtEPfvtOjOmKaui4EOpFI6zZc=",
    version = "v0.3.0",
)

go_repository(
    name = "com_github_azure_go_autorest_autorest_to",
    importpath = "github.com/Azure/go-autorest/autorest/to",
    sum = "h1:zebkZaadz7+wIQYgC7GXaz3Wb28yKYfVkkBKwc38VF8=",
    version = "v0.3.0",
)

go_repository(
    name = "com_github_azure_go_autorest_autorest_validation",
    importpath = "github.com/Azure/go-autorest/autorest/validation",
    sum = "h1:ISSNzGUh+ZSzizJWOWzs8bwpXIePbGLW4z/AmUFGH5A=",
    version = "v0.1.0",
)

go_repository(
    name = "com_github_azure_go_autorest_logger",
    importpath = "github.com/Azure/go-autorest/logger",
    sum = "h1:ruG4BSDXONFRrZZJ2GUXDiUyVpayPmb1GnWeHDdaNKY=",
    version = "v0.1.0",
)

go_repository(
    name = "com_github_azure_go_autorest_tracing",
    importpath = "github.com/Azure/go-autorest/tracing",
    sum = "h1:TRn4WjSnkcSy5AEG3pnbtFSwNtwzjr4VYyQflFE619k=",
    version = "v0.5.0",
)

go_repository(
    name = "com_github_bgentry_speakeasy",
    importpath = "github.com/bgentry/speakeasy",
    sum = "h1:ByYyxL9InA1OWqxJqqp2A5pYHUrCiAL6K3J+LKSsQkY=",
    version = "v0.1.0",
)

go_repository(
    name = "com_github_blang_semver",
    importpath = "github.com/blang/semver",
    sum = "h1:CGxCgetQ64DKk7rdZ++Vfnb1+ogGNnB17OJKJXD2Cfs=",
    version = "v3.5.0+incompatible",
)

go_repository(
    name = "com_github_briandowns_spinner",
    importpath = "github.com/briandowns/spinner",
    sum = "h1:GMmnK0dvr0Sf0gx3DvTbln0c8DE07B7sPVD9dgHOqo4=",
    version = "v0.0.0-20190319032542-ac46072a5a91",
)

go_repository(
    name = "com_github_burntsushi_xgb",
    importpath = "github.com/BurntSushi/xgb",
    sum = "h1:1BDTz0u9nC3//pOCMdNH+CiXJVYJh5UQNCOBG7jbELc=",
    version = "v0.0.0-20160522181843-27f122750802",
)

go_repository(
    name = "com_github_caarlos0_env_v6",
    importpath = "github.com/caarlos0/env/v6",
    sum = "h1:NZt6FAoB8ieKO5lEwRdwCzYxWFx7ZYF2R7UcoyaWtyc=",
    version = "v6.0.0",
)

go_repository(
    name = "com_github_cenkalti_backoff",
    importpath = "github.com/cenkalti/backoff",
    sum = "h1:tNowT99t7UNflLxfYYSlKYsBpXdEet03Pg2g16Swow4=",
    version = "v2.2.1+incompatible",
)

go_repository(
    name = "com_github_census_instrumentation_opencensus_proto",
    importpath = "github.com/census-instrumentation/opencensus-proto",
    sum = "h1:glEXhBS5PSLLv4IXzLA5yPRVX4bilULVyxxbrfOtDAk=",
    version = "v0.2.1",
)

go_repository(
    name = "com_github_envoyproxy_go_control_plane",
    importpath = "github.com/envoyproxy/go-control-plane",
    sum = "h1:rEvIZUSZ3fx39WIi3JkQqQBitGwpELBIYWeBVh6wn+E=",
    version = "v0.9.4",
)

go_repository(
    name = "com_github_envoyproxy_protoc_gen_validate",
    importpath = "github.com/envoyproxy/protoc-gen-validate",
    sum = "h1:EQciDnbrYxy13PgWoY8AqoxGiPrpgBZ1R8UNe3ddc+A=",
    version = "v0.1.0",
)

go_repository(
    name = "com_github_niemeyer_pretty",
    importpath = "github.com/niemeyer/pretty",
    sum = "h1:fD57ERR4JtEqsWbfPhv4DMiApHyliiK5xCTNVSPiaAs=",
    version = "v0.0.0-20200227124842-a10e7caefd8e",
)

go_repository(
    name = "com_github_opencontainers_umoci",
    importpath = "github.com/opencontainers/umoci",
    sum = "h1:6JA6emg6B0/8EhBw8i010nkXCnB1skxW+FQPFDJDzoA=",
    version = "v0.4.7-0.20200704224433-977db481b72c",
)

go_repository(
    name = "in_gopkg_yaml_v3",
    importpath = "gopkg.in/yaml.v3",
    sum = "h1:tQIYjPdBoyREyB9XMu+nnTclpTYkz2zFM+lzLJFO4gQ=",
    version = "v3.0.0-20200615113413-eeeca48fe776",
)

go_repository(
    name = "org_golang_google_protobuf",
    importpath = "google.golang.org/protobuf",
    sum = "h1:UhZDfRO8JRQru4/+LlLE0BRKGF8L+PICnvYZmx/fEGA=",
    version = "v1.24.0",
)

go_repository(
    name = "com_github_briandowns_spinner",
    importpath = "github.com/briandowns/spinner",
    sum = "h1:OixPqDEcX3juo5AjQZAnFPbeUA0jvkp2qzB5gOZJ/L0=",
    version = "v1.11.1",
)

go_repository (
    name = "com_github_99designs_gqlgen",
    importpath = "github.com/99designs/gqlgen",
    sum = "h1:oFSxl1DFS9X///uHV3y6CEfpcXWrDUxVblR4Xib2bs4=",
    version = "v0.11.3",
)

go_repository(
    name = "com_github_agnivade_levenshtein",
    importpath = "github.com/agnivade/levenshtein",
    sum = "h1:M5ZnqLOoZR8ygVq0FfkXsNOKzMCk0xRiow0R5+5VkQ0=",
    version = "v1.0.3",
)

go_repository(
    name = "com_github_andreyvit_diff",
    importpath = "github.com/andreyvit/diff",
    sum = "h1:bvNMNQO63//z+xNgfBlViaCIJKLlCJ6/fmUseuG0wVQ=",
    version = "v0.0.0-20170406064948-c7f18ee00883",
)

go_repository(
    name = "com_github_arbovm_levenshtein",
    importpath = "github.com/arbovm/levenshtein",
    sum = "h1:jfIu9sQUG6Ig+0+Ap1h4unLjW6YQJpKZVmUzxsD4E/Q=",
    version = "v0.0.0-20160628152529-48b4e1c0c4d0",
)

go_repository(
    name = "com_github_dgryski_trifles",
    importpath = "github.com/dgryski/trifles",
    sum = "h1:TUuUh0Xgj97tLMNtWtNvI9mIV6isjEb9lBMNv+77IGM=",
    version = "v0.0.0-20190318185328-a8d75aae118c",
)

go_repository(
    name = "com_github_logrusorgru_aurora",
    importpath = "github.com/logrusorgru/aurora",
    sum = "h1:bqDmpDG49ZRnB5PcgP0RXtQvnMSgIF14M7CBd2shtXs=",
    version = "v0.0.0-20200102142835-e9ef32dff381",
)

go_repository(
    name = "com_github_matryer_moq",
    importpath = "github.com/matryer/moq",
    sum = "h1:reVOUXwnhsYv/8UqjvhrMOu5CNT9UapHFLbQ2JcXsmg=",
    version = "v0.0.0-20200106131100-75d0ddfc0007",
)

go_repository(
    name = "com_github_opentracing_basictracer_go",
    importpath = "github.com/opentracing/basictracer-go",
    sum = "h1:YyUAhaEfjoWXclZVJ9sGoNct7j4TVk7lZWlQw5UXuoo=",
    version = "v1.0.0",
)

go_repository(
    name = "com_github_opentracing_opentracing_go",
    importpath = "github.com/opentracing/opentracing-go",
    sum = "h1:3jA2P6O1F9UOrWVpwrIo17pu01KWvNWg4X946/Y5Zwg=",
    version = "v1.0.2",
)

go_repository(
    name = "com_github_rs_cors",
    importpath = "github.com/rs/cors",
    sum = "h1:G9tHG9lebljV9mfp9SNPDL36nCDxmo3zTlAf1YgvzmI=",
    version = "v1.6.0",
)

go_repository(
    name = "com_github_shurcool_httpfs",
    importpath = "github.com/shurcooL/httpfs",
    sum = "h1:SWV2fHctRpRrp49VXJ6UZja7gU9QLHwRpIPBN89SKEo=",
    version = "v0.0.0-20171119174359-809beceb2371",
)

go_repository(
    name = "com_github_shurcool_vfsgen",
    importpath = "github.com/shurcooL/vfsgen",
    sum = "h1:JJV9CsgM9EC9w2iVkwuz+sMx8yRFe89PJRUrv6hPCIA=",
    version = "v0.0.0-20180121065927-ffb13db8def0",
)

go_repository(
    name = "com_github_vektah_dataloaden",
    importpath = "github.com/vektah/dataloaden",
    sum = "h1:+w0Zm/9gaWpEAyDlU1eKOuk5twTjAjuevXqcJJw8hrg=",
    version = "v0.2.1-0.20190515034641-a19b9a6e7c9e",
)

go_repository(
    name = "com_github_vektah_gqlparser_v2",
    importpath = "github.com/vektah/gqlparser/v2",
    sum = "h1:xgl5abVnsd4hkN9rk65OJID9bfcLSMuTaTcZj777q1o=",
    version = "v2.0.1",
)

go_repository(
    name = "com_sourcegraph_sourcegraph_appdash",
    importpath = "sourcegraph.com/sourcegraph/appdash",
    sum = "h1:d2maSb13hr/ArmfK3rW+wNUKKfytCol7W1/vDHxMPiE=",
    version = "v0.0.0-20180110180208-2cc67fd64755",
)

go_repository(
    name = "com_sourcegraph_sourcegraph_appdash_data",
    importpath = "sourcegraph.com/sourcegraph/appdash-data",
    sum = "h1:e1sMhtVq9AfcEy8AXNb8eSg6gbzfdpYhoNqnPJa+GzI=",
    version = "v0.0.0-20151005221446-73f23eafcf67",
)

go_repository(
    name = "com_github_apex_logs",
    importpath = "github.com/apex/logs",
    sum = "h1:38kpVK7Mw7yB9qrXQRXgdHcRQlmN8eORePFonYDuJsk=",
    version = "v0.0.7",
)

go_repository(
    name = "com_github_cheggaaa_pb_v3",
    importpath = "github.com/cheggaaa/pb/v3",
    sum = "h1:8WApbyUmgMOz7WIxJVNK0IRDcRfAmTxcEdi0TuxjdP4=",
    version = "v3.0.3",
)

go_repository(
    name = "com_github_cncf_udpa_go",
    importpath = "github.com/cncf/udpa/go",
    sum = "h1:WBZRG4aNOuI15bLRrCgN8fCq8E5Xuty6jGbmSNEvSsU=",
    version = "v0.0.0-20191209042840-269d4d468f6f",
)

go_repository(
    name = "com_github_cockroachdb_datadriven",
    importpath = "github.com/cockroachdb/datadriven",
    sum = "h1:OaNxuTZr7kxeODyLWsRMC+OD03aFUH+mW6r2d+MWa5Y=",
    version = "v0.0.0-20190809214429-80d97fb3cbaa",
)

go_repository(
    name = "com_github_containerd_containerd",
    importpath = "github.com/containerd/containerd",
    sum = "h1:LoIzb5y9x5l8VKAlyrbusNPXqBY0+kviRloxFUMFwKc=",
    version = "v1.3.3",
)

go_repository(
    name = "com_github_containerd_continuity",
    importpath = "github.com/containerd/continuity",
    sum = "h1:TP+534wVlf61smEIq1nwLLAjQVEK2EADoW3CX9AuT+8=",
    version = "v0.0.0-20190426062206-aaeac12a7ffc",
)

go_repository(
    name = "com_github_coreos_go_etcd",
    importpath = "github.com/coreos/go-etcd",
    sum = "h1:bXhRBIXoTm9BYHS3gE0TtQuyNZyeEMux2sDi4oo5YOo=",
    version = "v2.0.0+incompatible",
)

go_repository(
    name = "com_github_dustin_go_humanize",
    importpath = "github.com/dustin/go-humanize",
    sum = "h1:VSnTsYCnlFHaM2/igO1h6X3HA71jcobQuxemgkq4zYo=",
    version = "v1.0.0",
)

go_repository(
    name = "com_github_go_resty_resty_v2",
    importpath = "github.com/go-resty/resty/v2",
    sum = "h1:JOOeAvjSlapTT92p8xiS19Zxev1neGikoHsXJeOq8So=",
    version = "v2.3.0",
)

go_repository(
    name = "com_github_mattn_go_runewidth",
    importpath = "github.com/mattn/go-runewidth",
    sum = "h1:Ei8KR0497xHyKJPAv59M1dkC+rOZCMBJ+t3fZ+twI54=",
    version = "v0.0.7",
)

go_repository(
    name = "com_github_olekukonko_tablewriter",
    importpath = "github.com/olekukonko/tablewriter",
    sum = "h1:vHD/YYe1Wolo78koG299f7V/VAS08c6IpCLn+Ejf/w8=",
    version = "v0.0.4",
)

go_repository(
    name = "org_golang_x_exp",
    importpath = "golang.org/x/exp",
    sum = "h1:c2HOrn5iMezYjSlGPncknSEr/8x5LELb/ilJbXi9DEA=",
    version = "v0.0.0-20190121172915-509febef88a4",
)
