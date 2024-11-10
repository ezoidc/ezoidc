package main

import (
	"fmt"
	"strings"

	"gopkg.in/yaml.v3"
)

type Test struct {
	Error []string
}

var t = &Test{}

func (t *Test) Errorf(format string, args ...any) {
	t.Error = append(t.Error, fmt.Sprintf(format, args...))
}

func (t *Test) Check() error {
	if len(t.Error) > 0 {
		return fmt.Errorf("tests failed:\n%s", strings.Join(t.Error, "\n"))
	}
	return nil
}

type Configuration struct {
	Policy    string         `json:"policy"`
	Variables map[string]any `json:"variables"`
	Audience  string         `json:"audience"`
	Issuers   map[string]any `json:"issuers"`
	Listen    string         `json:"host"`
}

type Variables struct {
	Variables []struct {
		Name  string `json:"name"`
		Value struct {
			String string `json:"string"`
		} `json:"value"`
		Export string `json:"export"`
		Redact *bool  `json:"redact,omitempty"`
	}
}

func (v *Variables) Values() map[string]string {
	m := map[string]string{}
	for _, variable := range v.Variables {
		m[variable.Name] = variable.Value.String
	}
	return m
}

func (v *Variables) Exports() map[string]string {
	m := map[string]string{}
	for _, variable := range v.Variables {
		if variable.Export == "" {
			continue
		}
		m[variable.Name] = variable.Export
	}
	return m
}

func (c *Configuration) MarshalYAML() string {
	s, _ := yaml.Marshal(c)
	return string(s)
}
