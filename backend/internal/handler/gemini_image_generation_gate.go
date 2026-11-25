package handler

import (
	"github.com/gin-gonic/gin"
	"github.com/jk-zhang-meta/berth/internal/service"
)

// geminiImageGenerationRejected 在选号之前按客户端请求名、渠道映射名与请求体
// 执行 Gemini 系分组的生图门禁。命中时把请求标记为本地功能门禁并返回 true，
// 调用方按入口协议写出 400；账号级模型映射之后的判定由转发层负责。
func geminiImageGenerationRejected(c *gin.Context, apiKey *service.APIKey, body []byte, models ...string) bool {
	if apiKey == nil || !service.GeminiImageGenerationDenied(apiKey.Group, body, models...) {
		return false
	}
	service.MarkOpsClientBusinessLimited(c, service.OpsClientBusinessLimitedReasonLocalFeatureGate)
	return true
}
