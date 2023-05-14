package main

import (
	"fmt"
	//"net"
	"regexp"
	"strings"

)

type FieldCriteria struct {
	FieldName string              `json:"field"`
	Op        string              `json:"op"`
	Value     string              `json:"value"`
}

type ExpectedEvent struct {
	Id          string            `json:"id"`
	EventType   string            `json:"event_type"`
	SubType     string            `json:"sub_type"`
	FieldChecks []FieldCriteria   `json:"field_checks"`

	Matches     []EventWrapper   `json:"matches,omitempty"`
}

type CorrelationRow struct {
	Id string                     `json:"id"`
	Type string                   `json:"type"`
	SubType string                `json:"sub_type"`
	EventIndexes []string         `json:"indexes"`
	IsMet bool                    `json:"is_met"`
}

type MitreTestCriteria struct {
	Technique string                `json:"technique"`
	TestIndex uint                  `json:"test_index"`
	TestName  string                `json:"test_name"`
	ExpectedEvents []*ExpectedEvent `json:"expected_events"`
	ExpectedCorrelations []*CorrelationRow  `json:"exp_correlations,omitempty"`
}

type ExtractState struct {
	StartTime   uint64            `json:"start_time"`
	EndTime     uint64            `json:"end_time"`
	TestData    MitreTestCriteria `json:"test_data"`
	TotalEvents uint64            `json:"total_events"`
	NumMatches  uint64            `json:"num_matches"`
	Coverage    float64           `json:"coverage"`
}

// TestStatus shared with harness in summary json

type TestStatus int

const (
    StatusUnknown TestStatus = iota
    StatusMiscError             // 1
    StatusAtomicNotFound        // 2
    StatusCriteriaNotFound      // 3
    StatusSkipped               // 4
    StatusInvalidArguments      // 5
    StatusRunnerFailure         // 6
    StatusPreReqFail            // 7
    StatusTestFail              // 8
    StatusTestSuccess           // 9
    StatusTelemetryToolFailure  // 10
    StatusValidateFail          // 11
    StatusValidatePartial       // 12
    StatusValidateSuccess       // 13
    StatusDelegateValidation    // 14
)

func CheckMatch(haystack,op,needle string) bool {
	if gVerbose {
		l.Println("CheckMatch",op,"\"" + haystack + "\"",needle)
	}
	switch op {
	case "=":
		return haystack == needle
	case "~=":
		return strings.Contains(haystack,needle)
	case "*=":
		// TODO: only want to compile this once
		rx,err := regexp.Compile(needle)
		if err != nil {
			l.Println("invalid regex",needle,err)
			return false
		}
		return rx.MatchString(haystack)
	default:
		l.Println("ERROR: unsupported operator", op)
	}
	return false
}

func UpdateCoverage() {
	numFound := 0
	numExpected := len(gValidateState.TestData.ExpectedEvents) +
		len(gValidateState.TestData.ExpectedCorrelations)

	for _,exp := range gValidateState.TestData.ExpectedEvents {
		if len(exp.Matches)  > 0 {
			numFound += 1
		}
	}

	for _,exp := range gValidateState.TestData.ExpectedCorrelations {
		if exp.IsMet {
			numFound += 1
		}
	}

	prev := gValidateState.Coverage
	gValidateState.Coverage = float64(numFound) / float64(numExpected)

	if gValidateState.Coverage >= 1.0 && prev != gValidateState.Coverage {
		l.Println("SUCCESS: Agent Telemetry Has Full Coverage")
	}
}

func GetTelemChar(exp *ExpectedEvent) string {
	switch strings.ToUpper(exp.EventType) {
	case "PROCESS": return "P"
	case "NETFLOW": return "N"
	case "FILE":
		if strings.ToUpper(exp.SubType) == "READ" {
			return "f"
		}
		return "F"
	case "FILEMOD": return "F"
		if strings.ToUpper(exp.SubType) == "READ" {
			return "f"
		}
		return "F"
	case "AUTH": return "A"
	case "PTRACE": return "T"
	case "NETSNIFF": return "S"
	case "ALERT": return "W"
	case "MODULE": return "M"
	case "VOLUME": return "V"
	default:
		break
	}

	fmt.Println("No char code for EventType:",exp.EventType)

	return "?"
}

func GetTelemTypes(criteria *MitreTestCriteria) string {
	s := ""
	for _,exp := range criteria.ExpectedEvents {
		c := GetTelemChar(exp)
		if len(exp.Matches) == 0 {
			s += "<" + c + ">"
		} else {
			s += c
		}
	}
	for _,exp := range criteria.ExpectedCorrelations {
		c := "C"
		if exp.IsMet == false {
			s += "<" + c + ">"
		} else {
			s += c
		}
	}
	return s
}
