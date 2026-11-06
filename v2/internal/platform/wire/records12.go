package wire

import (
	"bytes"
	"encoding/json"
	"strconv"
	"sync"

	"github.com/QgMixtate/surveyscan/v2/contracts"
	"github.com/QgMixtate/surveyscan/v2/internal/platform/domain"
	jsonschema "github.com/santhosh-tekuri/jsonschema/v6"
)

const RecordPage12MaxItems = 100
const RecordPage12MaxBytes = 2 << 20

var recordPage12Once sync.Once
var recordPage12Compiled *jsonschema.Schema
var recordPage12CompileErr error

func recordPage12Schema() (*jsonschema.Schema, error) {
	recordPage12Once.Do(func() { recordPage12Compiled, recordPage12CompileErr = compileRecordPage12() })
	return recordPage12Compiled, recordPage12CompileErr
}

func compileRecordPage12() (*jsonschema.Schema, error) {
	b, err := contracts.C15API12Files.ReadFile("c15-records.schema.json")
	if err != nil {
		return nil, err
	}
	doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(b))
	if err != nil {
		return nil, err
	}
	c := jsonschema.NewCompiler()
	c.AssertFormat()
	id := "urn:surveyscan:c15:record-page:1:2"
	if err = c.AddResource(id, doc); err != nil {
		return nil, err
	}
	return c.Compile(id)
}

// RecordJSON preserves JSON string data without HTML expansion. This output is
// served as application/json with nosniff, never interpolated into an HTML page.
func RecordJSON(v any) ([]byte, error) {
	var b bytes.Buffer
	encoder := json.NewEncoder(&b)
	encoder.SetEscapeHTML(false)
	err := encoder.Encode(v)
	return b.Bytes(), err
}

func ValidateRecordPage12(b []byte) error {
	if len(b) == 0 || len(b) > RecordPage12MaxBytes {
		return domain.Invalid
	}
	schema, err := recordPage12Schema()
	if err != nil {
		return err
	}
	doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(b))
	if err != nil || !bounded(doc, 0) || schema.Validate(doc) != nil {
		return domain.Invalid
	}
	if _, err = Canonical(b); err != nil {
		return domain.Invalid
	}
	var page contracts.RecordFactPage12
	if json.Unmarshal(b, &page) != nil {
		return domain.Invalid
	}
	if _, err = strconv.ParseUint(page.Revision, 10, 64); err != nil || (page.Revision == "0") != (page.State == nil) || page.NextCursor != nil && len(page.Items) == 0 || page.State == nil && len(page.Items) != 0 {
		return domain.Invalid
	}
	previous := ""
	for _, item := range page.Items {
		key := item.Record + "/" + item.Field
		if key <= previous {
			return domain.Invalid
		}
		previous = key
	}
	return nil
}
