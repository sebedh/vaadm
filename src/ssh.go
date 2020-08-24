package main

import (
	"fmt"

	"github.com/hashicorp/vault/api"
	"gopkg.in/yaml.v2"
)

type SshRole struct {
	Name             string      `yaml:"name"`
	Key_type         string      `yaml:"key_type"`
	allowed_users    []string    `yaml:"allowed_users"`
	default_username string      `yaml:"default_user"`
	client           *api.Client `yaml:"-"`
}

func (s *SshRole) importYaml(yml []byte) error {
	if err := yaml.Unmarshal(yml, s); err != nil {
		return fmt.Errorf("Could not parse SSH yml")
	}
	return nil
}

func (s *SshRole) importVault() error {
	return nil
}
