package main

import (
)
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

