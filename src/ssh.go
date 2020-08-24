package main

import (
	"fmt"

	"gopkg.in/yaml.v2"
)

type Ssh_role struct {
	Name             string   `yaml:"name"`
	Key_type         string   `yaml:"key_type"`
	allowed_users    []string `yaml:"allowed_users"`
	default_username string   `yaml:"default_user"`
}

func (s *Ssh_role) importYaml(yml []byte) error {
	if err := yaml.Unmarshal(yml, s); err != nil {
		return fmt.Errorf("Could not parse SSH yml")
	}
	return nil
}
