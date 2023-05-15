package main

import (
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

