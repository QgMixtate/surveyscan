//go:build windows

package diskspool

import "path/filepath"

// Atomic заменяет файл через winstate (stage + POSIX-rename + flush). Требует блокировки
// каталога, взятой Lock в этом процессе. Гарантия — атомарная видимость имени и
// переживание падения процесса; физическая потеря питания этим не доказана.
func Atomic(path string, raw []byte) error {
	h, e := holder(filepath.Dir(path))
	if e != nil {
		return e
	}
	return h.root.AtomicReplace(filepath.Base(path), raw)
}

// SyncDir: AtomicReplace уже сбрасывает данные файла до и после rename, а у каталога
// на Windows нет сопоставимого fsync. Операция проверяет владение блокировкой и не
// заявляет большей долговечности, чем даёт Atomic.
func SyncDir(directory string) error {
	_, e := holder(directory)
	return e
}

// RecoverTemps допустим только при эксклюзивной блокировке: удаляет остатки .tmp-*.
func RecoverTemps(directory string) error {
	h, e := holder(directory)
	if e != nil {
		return e
	}
	_, e = h.root.RecoverOrphans()
	return e
}
