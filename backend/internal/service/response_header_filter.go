package service

import (
	"github.com/jk-zhang-meta/berth/internal/config"
	"github.com/jk-zhang-meta/berth/internal/util/responseheaders"
)

func compileResponseHeaderFilter(cfg *config.Config) *responseheaders.CompiledHeaderFilter {
	if cfg == nil {
		return nil
	}
	return responseheaders.CompileHeaderFilter(cfg.Security.ResponseHeaders)
}
