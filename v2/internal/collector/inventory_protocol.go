package collector

import (
	"github.com/QgMixtate/surveyscan/v2/contracts"
	"github.com/QgMixtate/surveyscan/v2/internal/platform/wire"
)

func (c *Collector) observation(raw []byte) (contracts.SignedObservation, contracts.Observation, []byte, error) {
	if c.protocol != nil {
		return c.protocol.Observation(raw)
	}
	return c.wire.Observation(raw)
}

func (c *Collector) decodeBatch(raw []byte) (wire.DecodedInventoryBatch, error) {
	d := c.protocol
	if d == nil {
		var err error
		d, err = wire.NewInventoryDecoder(c.wire, false)
		if err != nil {
			return wire.DecodedInventoryBatch{}, err
		}
	}
	return d.Batch(raw)
}
