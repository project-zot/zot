module github.com/anuvu/zot

go 1.16

require (
	github.com/99designs/gqlgen v0.14.0
	github.com/AdaLogics/go-fuzz-headers v0.0.0-20210921152813-f50b76b2163b // indirect
	github.com/Masterminds/semver v1.5.0
	github.com/alecthomas/template v0.0.0-20190718012654-fb15b899a751
	github.com/apex/log v1.9.0
	github.com/aquasecurity/trivy v0.0.0-00010101000000-000000000000
	github.com/aquasecurity/trivy-db v0.0.0-20210916043317-726b7b72a47b
	github.com/briandowns/spinner v1.16.0
	github.com/chartmuseum/auth v0.5.0
	github.com/containerd/containerd v1.5.8 // indirect
	github.com/containers/common v0.44.3
	github.com/containers/image/v5 v5.16.1
	github.com/docker/distribution v2.7.1+incompatible
	github.com/dustin/go-humanize v1.0.0
	github.com/fsnotify/fsnotify v1.5.1
	github.com/getlantern/deepcopy v0.0.0-20160317154340-7f45deb8130a
	github.com/go-ldap/ldap/v3 v3.4.1
	github.com/gofrs/uuid v4.1.0+incompatible
	github.com/google/go-containerregistry v0.7.0
	github.com/gorilla/handlers v1.5.1
	github.com/gorilla/mux v1.8.0
	github.com/json-iterator/go v1.1.12
	github.com/mitchellh/mapstructure v1.4.2
	github.com/nmcclain/ldap v0.0.0-20210720162743-7f8d1e44eeba
	github.com/olekukonko/tablewriter v0.0.5
	github.com/opencontainers/distribution-spec/specs-go v0.0.0-20211026153258-b3f631f25f1a
	github.com/opencontainers/go-digest v1.0.0
	github.com/opencontainers/image-spec v1.0.2-0.20210819154149-5ad6f50d6283
	github.com/opencontainers/umoci v0.4.8-0.20210922062158-e60a0cc726e6
	github.com/phayes/freeport v0.0.0-20180830031419-95f893ade6f2
	github.com/prometheus/client_golang v1.11.0
	github.com/prometheus/client_model v0.2.0
	github.com/rs/zerolog v1.26.0
	github.com/smartystreets/goconvey v1.7.2
	github.com/spf13/cobra v1.2.1
	github.com/spf13/viper v1.9.0
	github.com/stretchr/testify v1.7.0
	github.com/swaggo/http-swagger v1.1.2
	github.com/swaggo/swag v1.7.4
	github.com/urfave/cli/v2 v2.3.0
	github.com/vektah/gqlparser/v2 v2.2.0
	go.etcd.io/bbolt v1.3.6
	golang.org/x/crypto v0.0.0-20211108221036-ceb1ce70b4fa
	gopkg.in/resty.v1 v1.12.0
	gopkg.in/yaml.v2 v2.4.0
)

replace (
	github.com/aquasecurity/fanal => github.com/anuvu/fanal v0.0.0-20211007194926-d0c577a014df
	github.com/aquasecurity/trivy => github.com/anuvu/trivy v0.9.2-0.20211013001708-27408aa50da3
	github.com/aquasecurity/trivy-db => github.com/anuvu/trivy-db v0.0.0-20211007191113-44f7e57b689c
	github.com/containers/image/v5 => github.com/anuvu/image/v5 v5.0.0-20211118175920-feae9c2f0d91
)
