package imports

// Inventory12Enabled requires the admission decoder and transactional registry
// implementation to agree. A transport codec alone is not a capability offer.
func (s *UploadService) Inventory12Enabled() bool {
	if !s.Protocol.Supports12() {
		return false
	}
	registry, ok := s.Registry.(interface{ Inventory12Enabled() bool })
	return ok && registry.Inventory12Enabled()
}
