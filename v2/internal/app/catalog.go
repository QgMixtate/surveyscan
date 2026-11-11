// Package app is the composition root. Domain modules never import this package.
package app

import (
	"github.com/QgMixtate/surveyscan/v2/internal/modules/access"
	"github.com/QgMixtate/surveyscan/v2/internal/modules/assets"
	"github.com/QgMixtate/surveyscan/v2/internal/modules/audit"
	"github.com/QgMixtate/surveyscan/v2/internal/modules/cmdb"
	"github.com/QgMixtate/surveyscan/v2/internal/modules/imports"
	"github.com/QgMixtate/surveyscan/v2/internal/modules/inventory"
	"github.com/QgMixtate/surveyscan/v2/internal/modules/responsibility"
	"github.com/QgMixtate/surveyscan/v2/internal/modules/scope"
	"github.com/QgMixtate/surveyscan/v2/internal/modules/sources"
	"github.com/QgMixtate/surveyscan/v2/internal/platform/foundation"
	"github.com/QgMixtate/surveyscan/v2/internal/platform/messaging"
	"github.com/QgMixtate/surveyscan/v2/internal/platform/migrate"
)

func Migrations() ([]migrate.Migration, error) {
	providers := []func() ([]migrate.Migration, error){foundation.Migrations, access.Migrations, responsibility.Migrations, scope.Migrations, sources.Migrations, assets.Migrations, inventory.Migrations, cmdb.Migrations, imports.Migrations, audit.Migrations, messaging.Migrations}
	var all []migrate.Migration
	for _, provider := range providers {
		ms, err := provider()
		if err != nil {
			return nil, err
		}
		all = append(all, ms...)
	}
	return all, nil
}
