package cissors

// Location describes location of the Rule in a CIS benchmark
type Location struct {
	ID   string `yaml:"id" json:"id"`
	Name string `yaml:"name" json:"name"`
}

type RuleType string

const (
	Scored    RuleType = "Scored"
	NotScored RuleType = "Not Scored"
	Manual    RuleType = "Manual"
	Automated RuleType = "Automated"
)

// Rule describes a CIS benchmark rule
type Rule struct {
	ID       string            `yaml:"id" json:"id"`
	Name     string            `yaml:"name" json:"name"`
	RuleType RuleType          `yaml:"rule_type" json:"rule_type"`
	Location []Location        `yaml:"location,omitempty" json:"location,omitempty"`
	Sections map[string]string `yaml:"-,inline" json:"sections"`
}
