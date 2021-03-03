package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

// Config xxx
type Config struct {
	Direct []string `json:"direct"`
	Proxy  []string `json:"proxy"`
	Reject []string `json:"reject"`
}

// RuleType xx
type RuleType int

// Rules
const (
	RuleDomain RuleType = iota
	RuleCIDR
	RuleKeyword
)

// Rule xxx
type Rule struct {
	Type    RuleType
	Content string
}

func parseStringToRule(s string) (*Rule, error) {
	ss := strings.Split(s, ",")
	if len(ss) != 2 {
		return nil, fmt.Errorf("expect 2 fields, got %v", len(ss))
	}

	var r *Rule
	switch t, v := ss[0], ss[1]; t {
	case "DOMAIN-SUFFIX", "DOMAIN":
		r = &Rule{
			Type:    RuleDomain,
			Content: v,
		}
	case "DOMAIN-KEYWORD":
		r = &Rule{
			Type:    RuleKeyword,
			Content: v,
		}
	case "IP-CIDR":
		r = &Rule{
			Type:    RuleCIDR,
			Content: v,
		}
	}

	return r, nil
}

func parseIPFile(name string) ([]*Rule, error) {
	log.Printf("parse ip file: %v\n", name)
	buf, err := ioutil.ReadFile("data/" + name)
	if err != nil {
		log.Printf("read file %v error: %v\n", name, err)
		return nil, err
	}
	var content struct {
		Payload []string `yaml:"payload"`
	}

	err = yaml.Unmarshal(buf, &content)
	if err != nil {
		log.Printf("parse file %v error: %v", name, err)
		return nil, err
	}

	var rules []*Rule

	for _, s := range content.Payload {
		rules = append(rules, &Rule{
			Type:    RuleCIDR,
			Content: s,
		})
	}

	return rules, nil
}

func parseFile(name string) ([]*Rule, error) {
	log.Printf("parsing rule file %v\n", name)

	// check if ip file
	if strings.Contains(strings.ToLower(name), "ip") {
		return parseIPFile(name)
	}

	// default is yaml file
	buf, err := ioutil.ReadFile("data/" + name)
	if err != nil {
		log.Printf("read file %v error: %v\n", name, err)
		return nil, err
	}
	var content struct {
		Payload []string `yaml:"payload"`
	}

	err = yaml.Unmarshal(buf, &content)
	if err != nil {
		log.Printf("parse file %v error: %v", name, err)
		return nil, err
	}

	var rules []*Rule

	for _, s := range content.Payload {
		if rule, err := parseStringToRule(s); err != nil {
			log.Printf("parse string %q to rule error: %v", s, err)
			return nil, err
		} else {
			rules = append(rules, rule)
		}
	}

	return rules, nil
}

func main() {
	buf, err := ioutil.ReadFile("conf/config.json")
	if err != nil {
		log.Fatalf("open config file error: %v\n", err)
	}
	cfg := new(Config)
	err = json.Unmarshal(buf, cfg)

	if err != nil {
		log.Fatalf("parse config error: %v\n", err)
	}

	log.Printf("config file content: %+v\n", cfg)

	var rules []*Rule
	for _, file := range cfg.Direct {
		if rls, err := parseFile(file); err != nil {
			log.Printf("parse file %v error: %v\n", file, err)
		} else {
			fmt.Printf("parse file %v rules length: %v\n", file, len(rls))
			rules = append(rules, rls...)
		}
	}
	// merge files

	m := make(map[string]*Rule)
	for _, rule := range rules {
		key := strconv.FormatInt(int64(rule.Type), 10) + ":" + rule.Content
		if _, ok := m[key]; ok {
			log.Printf("rule %+v exists, skip add\n", rule)
		} else {
			m[key] = rule
		}
	}

	log.Printf("previous length %v, finally %v\n", len(rules), len(m))
}
