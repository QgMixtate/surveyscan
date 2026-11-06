package app

import (
	"errors"

	"github.com/QgMixtate/surveyscan/v2/contracts"
	"github.com/QgMixtate/surveyscan/v2/internal/platform/wire"
)

// ConfigureInventoryProtocol12 is startup configuration, before publishing any
// handlers. The returned decoder must also be installed in UploadService.
func (r *Registry) ConfigureInventoryProtocol12(enabled bool) (*wire.InventoryDecoder, error) {
	if r.Machine != nil {
		return nil, errors.New("inventory protocol must be configured before machine handlers")
	}
	decoder, err := wire.NewInventoryDecoder(r.Wire, enabled)
	if err != nil {
		return nil, err
	}
	r.inventoryProtocol = decoder
	return decoder, nil
}

func (r *Registry) Inventory12Enabled() bool { return r != nil && r.inventoryProtocol.Supports12() }

func (r *Registry) observation(raw []byte) (contracts.SignedObservation, contracts.Observation, []byte, error) {
	if r.inventoryProtocol != nil {
		return r.inventoryProtocol.Observation(raw)
	}
	return r.Wire.Observation(raw)
}

func (a MachineRegistry) Inventory12Enabled() bool { return a.Registry.Inventory12Enabled() }
