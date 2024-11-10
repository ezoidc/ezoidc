package models

import (
	"encoding/json"
	"fmt"

	"gopkg.in/yaml.v3"
)

type Variable struct {
	Name   string        `json:"name,omitempty"`
	Value  VariableValue `json:"value,omitempty"`
	Export string        `json:"export,omitempty"`
	Redact *bool         `json:"redact,omitempty"`
}

type VariableValue struct {
	String   string `json:"string,omitempty"`
	Provider string `json:"-"`
	ID       string `json:"-"`
}

func (v *VariableValue) UnmarshalYAML(node *yaml.Node) error {
	switch node.Kind {
	case yaml.ScalarNode:
		*v = VariableValue{Provider: "string", ID: node.Value}
		return nil
	case yaml.MappingNode:
		var o map[string]string
		if err := node.Decode(&o); err != nil {
			return err
		}
		if len(o) > 1 {
			return fmt.Errorf("only one variable provider can be specified")
		}
		for provider, id := range o {
			*v = VariableValue{
				Provider: provider,
				ID:       id,
			}
			return nil
		}
		return nil

	}
	return fmt.Errorf("invalid node kind: %v", node.Kind)
}

func (v *VariableValue) UnmarshalJSON(data []byte) error {
	type alias VariableValue
	var o alias
	err := json.Unmarshal(data, &o)
	if err != nil {
		err := json.Unmarshal(data, &o.String)
		if err != nil {
			return err
		}
	}
	*v = VariableValue(o)
	return nil
}

func (v Variable) Resolve(value string) Variable {
	v.Value.String = value
	v.Value.Provider = ""
	v.Value.ID = ""
	return v
}
