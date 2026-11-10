package app

import (
	"context"
	"errors"
	"io"
	"net/http"
	"time"

	"github.com/QgMixtate/surveyscan/v2/internal/modules/access"
	"github.com/QgMixtate/surveyscan/v2/internal/platform/domain"
	"github.com/QgMixtate/surveyscan/v2/internal/platform/identifier"
	"github.com/QgMixtate/surveyscan/v2/internal/portable"
)

// portableImportTimeout — предел на загрузку и импорт одного пакета через API. Общие таймауты сервера
// (10 с) и контекст авторизации (5 с) рассчитаны на короткие запросы, поэтому здесь продлеваются явно.
const portableImportTimeout = 5 * time.Minute

// portableImportBudget — от начала запроса (включая приём тела); после него новые записи пакета не начинаются, ответ уходит с complete=false.
// Меньше portableImportTimeout и proxy_read_timeout 300 с в deploy/nginx.conf с запасом на запись в обработке.
const portableImportBudget = 4 * time.Minute

// portableImportHandler — HTTPS-путь C23.03: POST /api/v1/sources/{source_id}/portable-import, тело —
// portable-пакет (application/zip). Права sources:admin; tenant — только из учётных данных. Проверки те же,
// что у консольного portable-import (подписи, лимиты, карантин); повтор того же пакета идемпотентен, поэтому
// оборванную загрузку продолжают повторной отправкой.
func (r *Registry) portableImportHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.URL.RawQuery != "" {
			access.APIError(w, 400, "INVALID_QUERY")
			return
		}
		if r.Machine == nil || r.Machine.Sources == nil || !r.Inventory12Enabled() {
			access.APIError(w, 501, "CAPABILITY_NOT_ENABLED")
			return
		}
		source := req.PathValue("source_id")
		if !identifier.Valid(source) {
			access.APIError(w, 404, "NOT_FOUND")
			return
		}
		if ct := req.Header.Get("Content-Type"); ct != "application/zip" && ct != "application/octet-stream" {
			access.APIError(w, 415, "UNSUPPORTED_MEDIA_TYPE")
			return
		}
		id, _ := access.Identity(req.Context())
		deadline := time.Now().Add(portableImportTimeout)
		rc := http.NewResponseController(w)
		_ = rc.SetReadDeadline(deadline)
		_ = rc.SetWriteDeadline(deadline)
		ctx, cancel := context.WithDeadline(context.WithoutCancel(req.Context()), deadline)
		defer cancel()
		limit := portable.DefaultLimits().MaxPackageBytes
		data, e := io.ReadAll(http.MaxBytesReader(w, req.Body, limit))
		if e != nil {
			var tooBig *http.MaxBytesError
			if errors.As(e, &tooBig) {
				access.APIError(w, 413, "PAYLOAD_TOO_LARGE")
				return
			}
			access.APIError(w, 400, "INVALID_BODY")
			return
		}
		report, e := r.ImportPortableUntil(ctx, r.Machine.Sources, id.TenantID, source, data, deadline.Add(portableImportBudget-portableImportTimeout))
		if e != nil {
			switch {
			case errors.Is(e, domain.NotFound) || errors.Is(e, domain.Unauthorized):
				// чужой tenant, неизвестный или неактивный источник — не раскрывать различие
				access.APIError(w, 404, "NOT_FOUND")
			case errors.Is(e, portable.ErrLimits):
				access.APIError(w, 413, "PAYLOAD_TOO_LARGE")
			case errors.Is(e, domain.Invalid) || isPortableRejection(e):
				access.APIError(w, 422, "PACKAGE_REJECTED")
			default:
				registryError(w, e)
			}
			return
		}
		if e = r.Machine.Sources.AuditPortableImport(ctx, id.TenantID, id.UserID, source); e != nil {
			registryError(w, e)
			return
		}
		registryJSON(w, report)
	})
}

// isPortableRejection — пакет целиком не прошёл проверку формата или подписи (ничего не применено).
func isPortableRejection(e error) bool {
	return errors.Is(e, portable.ErrFormat) || errors.Is(e, portable.ErrSignature)
}
