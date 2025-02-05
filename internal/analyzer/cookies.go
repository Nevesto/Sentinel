package analyzer

import (
	"fmt"
	"net/http"
)

func CheckCookies(urlStr string) {
	urlStr = ensureProtocol(urlStr)

	resp, err := http.Get(urlStr)
	if err != nil {
		fmt.Printf("Error accessing %s: %v\n", urlStr, err)
		return
	}
	defer resp.Body.Close()

	fmt.Println("Collected cookies:")
	for _, cookie := range resp.Cookies() {
		fmt.Printf("  - %s: %s\n", cookie.Name, cookie.Value)
	}
}
