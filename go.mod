module github.com/anuvu/zot

go 1.16

require (
	github.com/99designs/gqlgen v0.12.2
	github.com/AdaLogics/go-fuzz-headers v0.0.0-20210921152813-f50b76b2163b // indirect
	github.com/AdamKorcz/go-fuzz-headers v0.0.0-20210312213058-32f4d319f0d2 // indirect
	github.com/Microsoft/hcsshim v0.8.17 // indirect
	github.com/alecthomas/template v0.0.0-20190718012654-fb15b899a751
	github.com/apex/log v1.9.0
	github.com/aquasecurity/trivy v0.0.0-00010101000000-000000000000
	github.com/briandowns/spinner v1.12.0
	github.com/chartmuseum/auth v0.4.5
	github.com/cpuguy83/go-md2man/v2 v2.0.1 // indirect
	github.com/dustin/go-humanize v1.0.0
	github.com/fsnotify/fsnotify v1.4.9
	github.com/getlantern/deepcopy v0.0.0-20160317154340-7f45deb8130a
	github.com/go-ldap/ldap/v3 v3.3.0
	github.com/gofrs/uuid v4.0.0+incompatible
	github.com/golang/snappy v0.0.4 // indirect
	github.com/google/go-containerregistry v0.6.0
	github.com/gorilla/handlers v1.5.1
	github.com/gorilla/mux v1.8.0
	github.com/hashicorp/go-multierror v1.1.1 // indirect
	github.com/json-iterator/go v1.1.11
	github.com/klauspost/compress v1.13.6 // indirect
	github.com/klauspost/pgzip v1.2.5 // indirect
	github.com/mitchellh/mapstructure v1.4.1
	github.com/moby/sys/mount v0.2.0 // indirect
	github.com/nmcclain/asn1-ber v0.0.0-20170104154839-2661553a0484 // indirect
	github.com/nmcclain/ldap v0.0.0-20191021200707-3b3b69a7e9e3
	github.com/olekukonko/tablewriter v0.0.5
	github.com/opencontainers/distribution-spec/specs-go v0.0.0-20210810194746-13fa739db32c
	github.com/opencontainers/go-digest v1.0.0
	github.com/opencontainers/image-spec v1.0.2-0.20190823105129-775207bd45b6
	github.com/opencontainers/umoci v0.4.8-0.20210922062158-e60a0cc726e6
	github.com/phayes/freeport v0.0.0-20180830031419-95f893ade6f2
	github.com/rootless-containers/proto v0.1.2
	github.com/rs/zerolog v1.22.0
	github.com/smartystreets/goconvey v1.6.4
	github.com/spf13/cobra v1.2.1
	github.com/spf13/viper v1.8.1
	github.com/stretchr/testify v1.7.0
	github.com/swaggo/http-swagger v1.0.0
	github.com/swaggo/swag v1.7.0
	github.com/urfave/cli v1.22.5 // indirect
	github.com/vektah/gqlparser/v2 v2.2.0
	go.etcd.io/bbolt v1.3.5
	golang.org/x/crypto v0.0.0-20210921155107-089bfa567519
	golang.org/x/sys v0.0.0-20210923061019-b8560ed6a9b7 // indirect
	gopkg.in/resty.v1 v1.12.0
	gopkg.in/yaml.v2 v2.4.0
)

replace (
	github.com/aquasecurity/fanal => github.com/anuvu/fanal v0.0.0-20200731014233-a1725a9d379f
	github.com/aquasecurity/trivy => github.com/anuvu/trivy v0.9.2-0.20200731014147-c5f97b59c172

	github.com/aquasecurity/trivy-db => github.com/anuvu/trivy-db v0.0.0-20200623200932-d185809a68f7
)
