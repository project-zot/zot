module github.com/anuvu/zot

go 1.13

require (
	github.com/GoogleCloudPlatform/docker-credential-gcr v1.5.0 // indirect
	github.com/Microsoft/go-winio v0.4.15-0.20190919025122-fc70bd9a86b5 // indirect
	github.com/alecthomas/template v0.0.0-20190718012654-fb15b899a751
	github.com/aquasecurity/go-dep-parser v0.0.0-20190819075924-ea223f0ef24b // indirect
	github.com/aquasecurity/testdocker v0.0.0-20200426142840-5f05bce6f12a // indirect
	github.com/aquasecurity/trivy v0.0.0-00010101000000-000000000000
	github.com/aquasecurity/trivy-db v0.0.0-20200616161554-cd5b3da29bc8 // indirect
	github.com/caarlos0/env/v6 v6.0.0 // indirect
	github.com/chartmuseum/auth v0.4.0
	github.com/cheggaaa/pb/v3 v3.0.3 // indirect
	github.com/deckarep/golang-set v1.7.1 // indirect
	github.com/getlantern/deepcopy v0.0.0-20160317154340-7f45deb8130a
	github.com/go-chi/chi v4.0.2+incompatible // indirect
	github.com/go-git/go-git/v5 v5.0.0 // indirect
	github.com/go-ldap/ldap/v3 v3.1.3
	github.com/gofrs/uuid v3.2.0+incompatible
	github.com/golang/protobuf v1.4.2 // indirect
	github.com/google/wire v0.3.0 // indirect
	github.com/gorilla/handlers v1.4.2
	github.com/gorilla/mux v1.7.4
	github.com/json-iterator/go v1.1.9
	github.com/knqyf263/go-apk-version v0.0.0-20200609155635-041fdbb8563f // indirect
	github.com/knqyf263/go-deb-version v0.0.0-20190517075300-09fca494f03d // indirect
	github.com/knqyf263/go-rpmdb v0.0.0-20190501070121-10a1c42a10dc // indirect
	github.com/knqyf263/go-version v1.1.1 // indirect
	github.com/knqyf263/nested v0.0.1 // indirect
	github.com/mitchellh/mapstructure v1.1.2
	github.com/nmcclain/asn1-ber v0.0.0-20170104154839-2661553a0484 // indirect
	github.com/nmcclain/ldap v0.0.0-20191021200707-3b3b69a7e9e3
	github.com/olekukonko/tablewriter v0.0.2-0.20190607075207-195002e6e56a // indirect
	github.com/openSUSE/umoci v0.4.6-0.20200320140503-9aa268eeb258
	github.com/opencontainers/distribution-spec v1.0.0-rc0
	github.com/opencontainers/go-digest v1.0.0-rc1
	github.com/opencontainers/image-spec v1.0.2-0.20190823105129-775207bd45b6
	github.com/phayes/freeport v0.0.0-20180830031419-95f893ade6f2
	github.com/rs/zerolog v1.17.2
	github.com/saracen/walker v0.0.0-20191201085201-324a081bae7e // indirect
	github.com/smartystreets/goconvey v1.6.4
	github.com/sosedoff/gitkit v0.2.0 // indirect
	github.com/spf13/cobra v0.0.5
	github.com/spf13/viper v1.6.1
	github.com/stretchr/testify v1.6.1 // indirect
	github.com/swaggo/http-swagger v0.0.0-20190614090009-c2865af9083e
	github.com/swaggo/swag v1.6.3
	github.com/testcontainers/testcontainers-go v0.3.1 // indirect
	github.com/twitchtv/twirp v5.10.1+incompatible // indirect
	github.com/urfave/cli/v2 v2.2.0 // indirect
	go.etcd.io/bbolt v1.3.4
	go.uber.org/atomic v1.5.1 // indirect
	go.uber.org/multierr v1.4.0 // indirect
	go.uber.org/zap v1.13.0 // indirect
	golang.org/x/crypto v0.0.0-20200302210943-78000ba7a073
	golang.org/x/oauth2 v0.0.0-20200107190931-bf48bf16ab8d // indirect
	gopkg.in/resty.v1 v1.12.0
)

replace github.com/aquasecurity/trivy => github.com/anuvu/trivy v0.9.2-0.20200624055514-7fa927d7ca1d

replace github.com/aquasecurity/fanal => github.com/anuvu/fanal v0.0.0-20200623180831-a648790ef38e

replace github.com/aquasecurity/trivy-db => github.com/anuvu/trivy-db v0.0.0-20200623200932-d185809a68f7
