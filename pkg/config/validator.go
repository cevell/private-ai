package config

import (
	"fmt"
)

// Validate checks the configuration for required fields and logical constraints.
func (s *NodeSpec) Validate() error {
	if len(s.Workload.Containers) == 0 && s.Workload.Port == 0 {
		return fmt.Errorf("node spec must declare at least one container or workload port")
	}

	for i, c := range s.Workload.Containers {
		if c.Name == "" {
			return fmt.Errorf("container #%d missing required name", i)
		}
		if c.Image == "" {
			return fmt.Errorf("container '%s' missing required image", c.Name)
		}
	}

	return nil
}
