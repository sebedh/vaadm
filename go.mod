module vaadm

go 1.15

require (
	github.com/golang/mock v1.4.3 // indirect
	github.com/hashicorp/vault/api v1.0.4
	github.com/mitchellh/go-homedir v1.1.0
	github.com/sebedh/vaadm/cmd v0.0.0-00010101000000-000000000000
	github.com/spf13/cobra v1.0.0
	github.com/spf13/viper v1.7.1
	gopkg.in/yaml.v2 v2.3.0
)

replace github.com/sebedh/vaadm/cmd => ./cmd
