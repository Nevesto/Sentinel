package analyzer

import (
	"strings"
)

func ensureProtocol(urlStr string) string {
	if !strings.HasPrefix(urlStr, "http://") && !strings.HasPrefix(urlStr, "https://") {
		urlStr = "https://" + urlStr
	}

	return urlStr
}
