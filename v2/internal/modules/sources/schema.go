package sources

import (
	"embed"
	"github.com/QgMixtate/surveyscan/v2/internal/platform/migrate"
)

//go:embed schema/*.sql
var files embed.FS

func Migrations() ([]migrate.Migration, error) { return migrate.FromFS("sources", files) }
