package analyzer

import (
	"fmt"
	"net/http"
)

func CheckSecurity(urlStr string) {
	urlStr = ensureProtocol(urlStr)

	resp, err := http.Get(urlStr)
	if err != nil {
		fmt.Printf("Error accessing %s: %v\n", urlStr, err)
		return
	}
	defer resp.Body.Close()

	if resp.Request.URL.Scheme != "https" {
		fmt.Println("Warning: The site does not use secure HTTPS!")
	} else {
		fmt.Println("The site uses secure HTTPS.")
	}

	fmt.Println("Security headers:")
	fmt.Printf("  - X-Content-Type-Options: %s\n", resp.Header.Get("X-Content-Type-Options"))
	fmt.Printf("  - Content-Security-Policy: %s\n", resp.Header.Get("Content-Security-Policy"))
}
