module github.com/anuvu/zot

go 1.16

require (
	github.com/99designs/gqlgen v0.13.0
	github.com/alecthomas/template v0.0.0-20190718012654-fb15b899a751
	github.com/apex/log v1.9.0
	github.com/aquasecurity/trivy v0.0.0-00010101000000-000000000000
	github.com/briandowns/spinner v1.16.0
	github.com/chartmuseum/auth v0.4.5
	github.com/docker/distribution v2.7.1+incompatible
	github.com/dustin/go-humanize v1.0.0
	github.com/fsnotify/fsnotify v1.5.1
	github.com/getlantern/deepcopy v0.0.0-20160317154340-7f45deb8130a
	github.com/go-ldap/ldap/v3 v3.4.1
	github.com/gofrs/uuid v4.0.0+incompatible
	github.com/google/go-containerregistry v0.6.0
	github.com/gorilla/handlers v1.5.1
	github.com/gorilla/mux v1.8.0
	github.com/json-iterator/go v1.1.11
	github.com/mitchellh/mapstructure v1.4.1
	github.com/moby/sys/mount v0.2.0 // indirect
	github.com/nmcclain/ldap v0.0.0-20210720162743-7f8d1e44eeba
	github.com/olekukonko/tablewriter v0.0.5
	github.com/opencontainers/distribution-spec/specs-go v0.0.0-20210830161531-162b5c95788b
	github.com/opencontainers/go-digest v1.0.0
	github.com/opencontainers/image-spec v1.0.2-0.20190823105129-775207bd45b6
	github.com/opencontainers/umoci v0.4.7
	github.com/phayes/freeport v0.0.0-20180830031419-95f893ade6f2
	github.com/rs/zerolog v1.24.0
	github.com/smartystreets/goconvey v1.6.4
	github.com/spf13/cobra v1.2.1
	github.com/spf13/viper v1.8.1
	github.com/stretchr/testify v1.7.0
	github.com/swaggo/http-swagger v1.1.1
	github.com/swaggo/swag v1.7.1
	github.com/vektah/gqlparser/v2 v2.1.0
	go.etcd.io/bbolt v1.3.6
	golang.org/x/crypto v0.0.0-20210817164053-32db794688a5
	gopkg.in/resty.v1 v1.12.0
	gopkg.in/yaml.v2 v2.4.0
)

replace github.com/aquasecurity/trivy => ../../anuvu/trivy

replace github.com/aquasecurity/fanal => ../../anuvu/fanal


replace github.com/aquasecurity/trivy-db => github.com/anuvu/trivy-db v0.0.0-20200623200932-d185809a68f7
