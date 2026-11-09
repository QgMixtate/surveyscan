package agent

// Коды этапов завершения RunWindows/RunLinux12 (попадают в код выхода службы).
const (
	StageState = 1 // состояние, блокировка, восстановление .tmp-*
	StageOpen  = 2 // Open: агент не зарегистрирован / нет доверенного сертификата
	StageSpool = 3 // очередь
	StageSetup = 4 // клиент 1.2, лимиты
)

// StageError помечает этап, на котором цикл агента завершился.
type StageError struct {
	Code uint32
	Err  error
}

func (e *StageError) Error() string { return e.Err.Error() }
func (e *StageError) Unwrap() error { return e.Err }

func stage(code uint32, e error) error { return &StageError{Code: code, Err: e} }
