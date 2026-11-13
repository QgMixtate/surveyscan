package collector

import "context"

// TargetSync — крючок целей удалённого сбора (C51.03, пакет collecttargets): задаётся при запуске collector.
// Связь через крючок, а не импорт: пакет агента в тестах сам импортирует collector.
func (c *Collector) syncTargets(run, task context.Context) error {
	if c.TargetSync == nil {
		return nil
	}
	return c.TargetSync(run, task)
}

// MachinePost — запрос к центру по mTLS личности collector (для крючков вроде collecttargets).
func (c *Collector) MachinePost(ctx context.Context, path string, raw []byte) (int, []byte, error) {
	return c.post(ctx, path, raw, "")
}
