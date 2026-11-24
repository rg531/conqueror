// Copyright 2026 Florian Krutzler
// SPDX-License-Identifier: Apache-2.0

package events

import (
	"encoding/json"
	"fmt"
	_ "conqueror/internal/logger"
	"log/slog"
	"sync"
)

// defined by user input:
type OutputMode string

const (
	Json OutputMode = "JSON"
	Log  OutputMode = "LOG"
)

var currentOutputMode OutputMode

// only used for logs:
type logMode string

const (
	Info          logMode = "INFO" // only for Log/Stdout (detailled status logs)
	Meta          logMode = "META" // only for JSON export (the most important INFO stuff)
	Error         logMode = "ERROR"
	Vulnerability logMode = "VULNERABILITY"
)

// area of vulnerability, only used for JSON structure:
type environment string

const (
	OS         environment = "operating_system"
	Docker     environment = "docker"
	Kubernetes environment = "kubernetes"
	Cloud      environment = "cloud"
	None       environment = ""
)

// structures and instance of result JSON:
type vulnerability struct {
	Environment string `json:"environment"`
	Type        string `json:"type"`
	Proof       string `json:"proof"`
}
type resultJson struct {
	Vulnerabilities []vulnerability   `json:"vulnerabilities"`
	Errors          []string          `json:"errors"`
	Metadata        map[string]string `json:"metadata"`
}

var (
	instance *resultJson
	once     sync.Once
)

// set if we use JSON oder STDOUT:
func SetMode(mode OutputMode) {
	currentOutputMode = mode
}

// get/initialize result JSON:
func getResultJson() *resultJson {
	once.Do(func() {
		instance = &resultJson{
			Vulnerabilities: []vulnerability{},
			Errors:          []string{},
			Metadata: map[string]string{
				"json_version": "2.0",
			},
		}
	})
	return instance
}

func HandleInfo(description string, proof string) {
	handleEvent(Info, None, description, nil, "", proof)
}

func HandleMetaInfo(description string, proof string) {
	handleEvent(Meta, None, description, nil, "", proof)
}

func HandleError(description string, err error) {
	handleEvent(Error, None, description, err, "", "")
}

func HandleVulnerability(environment environment, description string, vulnerabilityType string, proof string) {
	handleEvent(Vulnerability, environment, description, nil, vulnerabilityType, proof)
}

func handleEvent(logMode logMode, environment environment, description string, err error, vulnerabilityType string, proof string) {
	if currentOutputMode == Log {
		handleLogEvent(logMode, proof, description, err, vulnerabilityType)
	} else if currentOutputMode == Json && logMode == Vulnerability {
		handleJsonVulnerability(environment, vulnerabilityType, proof)
	} else if currentOutputMode == Json && logMode == Error {
		handleJsonError(description, err)
	} else if currentOutputMode == Json && logMode == Meta {
		handleJsonMetaData(description, proof)
	}
}

func handleJsonMetaData(key string, value string) {
	r := getResultJson()
	r.Metadata[key] = value
}

func handleJsonVulnerability(environment environment, vulnerabilityType string, proof string) {
	r := getResultJson()
	r.Vulnerabilities = append(r.Vulnerabilities, vulnerability{Environment: string(environment), Type: vulnerabilityType, Proof: proof})
}

func handleJsonError(description string, err error) {
	r := getResultJson()
	r.Errors = append(r.Errors, fmt.Sprintf("%s: %s", description, err))
}

// do not log Meta stuff cause we alredy got it via INFO.
func handleLogEvent(logMode logMode, proof string, description string, err error, vulnerabilityType string) {
	switch logMode {
	case Info:
		if proof == "" {
			slog.Info(description)
		} else {
			slog.Info(description, "proof", proof)
		}
	case Error:
		slog.Error(description, "error", err)
	case Vulnerability:
		slog.Warn(description, "vulnerability", vulnerabilityType, "proof", proof)
	}
}

func PrintJson() {
	r := getResultJson()
	bytes, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		fmt.Println("could not generate JSON:", err)
	}
	fmt.Println(string(bytes))
}
