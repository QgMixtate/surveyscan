//go:build windows

package winstate

import (
	"encoding/binary"
	"errors"
	"strings"
	"unicode/utf16"

	"golang.org/x/sys/windows"
)

const (
	// Предел делает восстановление ограниченным по времени и памяти: состояние агента
	// содержит единицы файлов, а тысячи записей означают порчу или подмену каталога.
	maxOrphanScan   = 4096
	maxOrphanDelete = 256
	orphanPrefix    = ".tmp-"
	// FILE_ID_BOTH_DIR_INFO на amd64: NextEntryOffset@0, FileAttributes@56,
	// FileNameLength@60, FileName@104.
	dirNameOffset = 104
)

// RecoverOrphans удаляет только остатки AtomicReplace (.tmp-*), которые оставил
// упавший процесс между созданием временного файла и rename. Требует эксклюзивной
// блокировки состояния, поэтому живой писатель не может быть затронут. Каждый
// кандидат открывается относительно корня теми же проверками, что и обычные файлы
// (не reparse, одна ссылка, приватный DACL): небезопасный остаток не удаляется и не
// «чинится», а возвращается как ошибка. Ничего за пределами префикса не трогается.
func (r *Root) RecoverOrphans() (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.writer == nil || r.writer.closed || r.handle == windows.InvalidHandle {
		return 0, ErrPrivate
	}
	names, err := r.orphanNames()
	if err != nil {
		return 0, err
	}
	removed := 0
	for _, name := range names {
		// Без разделения доступа: если кто-то держит файл, это не остаток.
		handle, err := r.open(name, windows.DELETE, windows.FILE_OPEN, 0)
		if err != nil {
			var missing *stateError
			if errors.As(err, &missing) && missing.stage == "relative_open" && missing.code == uint32(windows.ERROR_FILE_NOT_FOUND) {
				continue
			}
			return removed, err
		}
		mark := byte(1)
		var status windows.IO_STATUS_BLOCK
		err = windows.NtSetInformationFile(handle, &status, &mark, 1, windows.FileDispositionInformation)
		closeErr := windows.CloseHandle(handle)
		if err != nil {
			return removed, privateError("orphan_delete", err)
		}
		if closeErr != nil {
			return removed, ErrPrivate
		}
		removed++
	}
	return removed, nil
}

// orphanNames перечисляет имена каталога по дескриптору корня, а не по абсолютному
// пути. Имена — только кандидаты: безопасность проверяет r.open при удалении.
func (r *Root) orphanNames() ([]string, error) {
	var names []string
	buffer := make([]byte, 64*1024)
	class := uint32(windows.FileIdBothDirectoryRestartInfo)
	scanned := 0
	for {
		err := windows.GetFileInformationByHandleEx(r.handle, class, &buffer[0], uint32(len(buffer)))
		class = windows.FileIdBothDirectoryInfo
		if err != nil {
			if errors.Is(err, windows.ERROR_NO_MORE_FILES) {
				return names, nil
			}
			return nil, privateError("orphan_scan", err)
		}
		offset := 0
		for {
			if offset < 0 || offset+dirNameOffset > len(buffer) {
				return nil, ErrPrivate
			}
			next := int(binary.LittleEndian.Uint32(buffer[offset:]))
			length := int(binary.LittleEndian.Uint32(buffer[offset+60:]))
			if length%2 != 0 || offset+dirNameOffset+length > len(buffer) {
				return nil, ErrPrivate
			}
			scanned++
			if scanned > maxOrphanScan {
				return nil, ErrPrivate
			}
			chars := make([]uint16, length/2)
			for i := range chars {
				chars[i] = binary.LittleEndian.Uint16(buffer[offset+dirNameOffset+i*2:])
			}
			name := string(utf16.Decode(chars))
			if strings.HasPrefix(strings.ToLower(name), orphanPrefix) && fileName(name) {
				if len(names) >= maxOrphanDelete {
					return nil, ErrPrivate
				}
				names = append(names, name)
			}
			if next == 0 {
				break
			}
			offset += next
		}
	}
}
