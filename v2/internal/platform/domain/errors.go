package domain

import "errors"

var Invalid = errors.New("invalid input")
var Unauthorized = errors.New("source not authorized")
var Conflict = errors.New("immutable identity or sequence conflict")
var NotFound = errors.New("resource not found")
var Revision = errors.New("revision mismatch")

var DependencyUnavailable = errors.New("required key operation unavailable")
