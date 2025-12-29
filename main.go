package main

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path"
	"strings"

	"github.com/Danny-Dasilva/CycleTLS/cycletls"
	"github.com/manifoldco/promptui"
	"github.com/spf13/cobra"
	"go.nhat.io/cookiejar"
)

// Common constants for requests
const (
	userAgent = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36"
	ja3       = "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-13-18-51-45-43-27-17513,29-23-24,0"
)

func main() {
	var datDir string
	var debug bool
	var rootCmd = &cobra.Command{
		Use:   "masterclass-dl",
		Short: "A downloader for classes from masterclass.com",
	}
	rootCmd.PersistentFlags().StringVarP(&datDir, "datDir", "d", "", "Path to the directory where cookies and other data will be stored (default: $HOME/.masterclass/)")
	rootCmd.PersistentFlags().BoolVar(&debug, "debug", false, "Enable debug output")
	if datDir == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
		datDir = path.Join(home, ".masterclass")
	}

	if _, err := os.Stat(datDir); os.IsNotExist(err) {
		err := os.MkdirAll(datDir, 0755)
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
	}

	var outputDir string
	var downloadPdfs bool
	var downloadPosters bool
	var ytdlExec string
	var limit int
	var nameAsSeries bool
	var downloadCmd = &cobra.Command{
		Use:     "download [class/chapter/category...]",
		Aliases: []string{"dl"},
		Short:   "Download a class, chapter, or category from masterclass.com",
		Long: `Download a class, chapter, or category from masterclass.com.
You can either specify a url or just the id. You can specify multiple URLs to download multiple at once.

Supported URL formats:
  - Class:    https://www.masterclass.com/classes/gordon-ramsay-teaches-cooking
  - Chapter:  https://www.masterclass.com/classes/gordon-ramsay-teaches-cooking/chapters/introduction
  - Category: https://www.masterclass.com/homepage/science-and-tech`,
		Args: cobra.MatchAll(cobra.MinimumNArgs(1)),
		Run: func(cmd *cobra.Command, args []string) {
			for _, arg := range args {
				// Check if this is a category/homepage URL
				if strings.Contains(arg, "/homepage/") {
					err := downloadCategory(getClient(datDir), datDir, outputDir, downloadPdfs, downloadPosters, ytdlExec, limit, nameAsSeries, arg)
					if err != nil {
						fmt.Println(err)
					}
				} else {
					err := download(getClient(datDir), datDir, outputDir, downloadPdfs, downloadPosters, ytdlExec, nameAsSeries, arg)
					if err != nil {
						fmt.Println(err)
					}
				}
			}
		},
	}
	downloadCmd.Flags().StringVarP(&outputDir, "output", "o", "", "Output directory")
	downloadCmd.Flags().BoolVarP(&downloadPdfs, "pdfs", "p", true, "Download PDFs")
	downloadCmd.Flags().BoolVar(&downloadPosters, "posters", true, "Download poster and fanart images")
	downloadCmd.Flags().StringVarP(&ytdlExec, "ytdl-exec", "y", "yt-dlp", "Path to the youtube-dl or yt-dlp executable")
	downloadCmd.Flags().IntVarP(&limit, "limit", "l", 10, "Maximum number of classes to download from a category (0 for unlimited)")
	downloadCmd.Flags().BoolVar(&nameAsSeries, "name-files-as-series", false, "Name files in TV series format (s01e01-Title.mp4)")
	downloadCmd.MarkFlagRequired("output")

	var loginCmd = &cobra.Command{
		Use:   "login [email] [password]",
		Short: "Login to masterclass.com",
		Args:  cobra.ExactArgs(2),
		Run: func(cmd *cobra.Command, args []string) {
			email := args[0]
			password := args[1]
			err := login(getClient(datDir), datDir, email, password, debug)
			if err != nil {
				fmt.Println(err)
				return
			}
			fmt.Println("Login successful")
		},
	}

	var loginStatusCmd = &cobra.Command{
		Use:   "status",
		Short: "Check login status",
		Run: func(cmd *cobra.Command, args []string) {
			err := loginStatus(getClient(datDir), datDir)
			if err != nil {
				fmt.Println(err)
				return
			}
		},
	}

	rootCmd.AddCommand(downloadCmd)
	rootCmd.AddCommand(loginCmd)
	rootCmd.AddCommand(loginStatusCmd)

	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func getClient(datDir string) *http.Client {
	jar := cookiejar.NewPersistentJar(
		cookiejar.WithFilePath(path.Join(datDir, "cookies.json")),
		cookiejar.WithFilePerm(0755),
		cookiejar.WithAutoSync(true),
	)

	return &http.Client{
		Jar: jar,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{},
		},
	}
}

func login(client *http.Client, datDir string, email string, password string, debug bool) error {
	// Initialize CycleTLS client to bypass Cloudflare
	cycleclient := cycletls.Init()
	// Note: CycleTLS Close() has issues, so we'll use recover to handle panics
	defer func() {
		if r := recover(); r != nil {
			// Ignore panic from Close(), it's a known issue with CycleTLS
		}
	}()
	defer func() {
		cycleclient.Close()
	}()

	if debug {
		fmt.Printf("Attempting login with email: %s\n", email)
		fmt.Printf("Password length: %d characters\n", len(password))
		if len(password) > 0 {
			fmt.Printf("Password first char: %c, last char: %c\n", password[0], password[len(password)-1])
		}
	}

	// First, visit the home page to establish session (required for login to work)
	if debug {
		fmt.Println("Visiting home page...")
	}
	homePageResp, err := cycleclient.Do("https://www.masterclass.com/", cycletls.Options{
		Body:      "",
		Ja3:       ja3,
		UserAgent: userAgent,
	}, "GET")
	if err != nil {
		return fmt.Errorf("failed to visit home page: %v", err)
	}

	// Build cookie string from home page response
	var cookieStr string
	for _, cookie := range homePageResp.Cookies {
		if cookieStr != "" {
			cookieStr += "; "
		}
		cookieStr += cookie.Name + "=" + cookie.Value
	}

	// Now visit the login page with cookies from home page
	if debug {
		fmt.Println("Visiting login page...")
	}
	loginPageResp, err := cycleclient.Do("https://www.masterclass.com/auth/login", cycletls.Options{
		Body:      "",
		Ja3:       ja3,
		UserAgent: userAgent,
		Headers: map[string]string{
			"Referer": "https://www.masterclass.com/",
			"Cookie":  cookieStr,
		},
	}, "GET")
	if err != nil {
		return fmt.Errorf("failed to visit login page: %v", err)
	}

	if debug && strings.Contains(loginPageResp.Body, "hidden") {
		fmt.Println("Login page contains hidden form fields - might need to extract them")
	}

	// Update cookies from login page response
	for _, cookie := range loginPageResp.Cookies {
		// Check if cookie already exists, update it, otherwise append
		found := false
		for _, existing := range homePageResp.Cookies {
			if existing.Name == cookie.Name {
				existing.Value = cookie.Value
				found = true
				break
			}
		}
		if !found {
			homePageResp.Cookies = append(homePageResp.Cookies, cookie)
		}
	}

	// Rebuild cookie string with all cookies
	cookieStr = ""
	for _, cookie := range homePageResp.Cookies {
		if cookieStr != "" {
			cookieStr += "; "
		}
		cookieStr += cookie.Name + "=" + cookie.Value
	}

	// Get CSRF token
	if debug {
		fmt.Println("Getting CSRF token...")
	}
	csrfResp, err := cycleclient.Do("https://www.masterclass.com/api/v2/csrf-token", cycletls.Options{
		Body:      "",
		Ja3:       ja3,
		UserAgent: userAgent,
		Headers: map[string]string{
			"Referer": "https://www.masterclass.com/auth/login",
			"Cookie":  cookieStr,
		},
	}, "GET")
	if err != nil {
		return fmt.Errorf("failed to get CSRF token: %v", err)
	}
	if csrfResp.Status != 200 {
		return fmt.Errorf("failed to get CSRF token: status=%d, body=%s", csrfResp.Status, csrfResp.Body)
	}

	var csrfResponse CSRFResponse
	err = json.Unmarshal([]byte(csrfResp.Body), &csrfResponse)
	if err != nil {
		return fmt.Errorf("failed to parse CSRF response: %v", err)
	}
	if csrfResponse.Param == "" || csrfResponse.Token == "" || csrfResponse.Param != "authenticity_token" {
		return fmt.Errorf("invalid CSRF token response: param=%s, token=%s", csrfResponse.Param, csrfResponse.Token)
	}

	// Update cookies from CSRF response
	for _, cookie := range csrfResp.Cookies {
		// Check if cookie already exists, update it, otherwise append
		found := false
		for _, existing := range homePageResp.Cookies {
			if existing.Name == cookie.Name {
				existing.Value = cookie.Value
				found = true
				break
			}
		}
		if !found {
			homePageResp.Cookies = append(homePageResp.Cookies, cookie)
		}
	}

	// Rebuild cookie string
	cookieStr = ""
	for _, cookie := range homePageResp.Cookies {
		if cookieStr != "" {
			cookieStr += "; "
		}
		cookieStr += cookie.Name + "=" + cookie.Value
	}

	// Prepare login data - NO authenticity_token in the body! Only in X-Csrf-Token header
	data := url.Values{}
	data.Set("next_page", "")
	data.Set("auth_key", email)
	data.Set("password", password)
	data.Set("provider", "identity")

	if debug {
		fmt.Println("Logging in...")
		fmt.Printf("Form data: %s\n", data.Encode())
		fmt.Printf("CSRF token (header only): %s\n", csrfResponse.Token)
	}

	// Perform login - headers must match browser (cors, not navigate!)
	loginResp, err := cycleclient.Do("https://www.masterclass.com/auth/identity/callback", cycletls.Options{
		Body:      data.Encode(),
		Ja3:       ja3,
		UserAgent: userAgent,
		Headers: map[string]string{
			"Accept":             "*/*",
			"Accept-Language":    "en-GB,en-US;q=0.9,en;q=0.8",
			"Content-Type":       "application/x-www-form-urlencoded",
			"X-Csrf-Token":       csrfResponse.Token,
			"Cookie":             cookieStr,
			"Referer":            "https://www.masterclass.com/auth/login",
			"Origin":             "https://www.masterclass.com",
			"Sec-Ch-Ua":          "\"Chromium\";v=\"140\", \"Not=A?Brand\";v=\"24\", \"Google Chrome\";v=\"140\"",
			"Sec-Ch-Ua-Mobile":   "?0",
			"Sec-Ch-Ua-Platform": "\"macOS\"",
			"Sec-Fetch-Dest":     "empty",
			"Sec-Fetch-Mode":     "cors",
			"Sec-Fetch-Site":     "same-origin",
			"Priority":           "u=1, i",
		},
	}, "POST")
	if err != nil {
		return fmt.Errorf("failed to login: %v", err)
	}

	// Handle specific error statuses
	if loginResp.Status == 429 {
		return fmt.Errorf("rate limited by Masterclass. Please wait 15-60 minutes before trying again, or use a different network/VPN")
	}

	// Accept 200 or 302 (redirect) as success
	if loginResp.Status != 200 && loginResp.Status != 302 {
		return fmt.Errorf("failed to login: status=%d, body=%s", loginResp.Status, loginResp.Body)
	}

	if debug {
		fmt.Printf("Login response status: %d\n", loginResp.Status)
		fmt.Printf("Login response body length: %d bytes\n", len(loginResp.Body))
	}

	// Check if the HTML contains error indicators
	if strings.Contains(loginResp.Body, "Invalid email") ||
		strings.Contains(loginResp.Body, "Invalid password") ||
		strings.Contains(loginResp.Body, "incorrect email or password") {
		return fmt.Errorf("login failed: invalid credentials")
	}

	// Check all cookies in login response
	hasSessionCookie := false
	if debug {
		fmt.Printf("Number of cookies in login response: %d\n", len(loginResp.Cookies))
	}
	for _, cookie := range loginResp.Cookies {
		if debug {
			valuePreview := cookie.Value
			if len(valuePreview) > 50 {
				valuePreview = valuePreview[:50] + "..."
			}
			fmt.Printf("  Cookie: %s = %s (len: %d)\n", cookie.Name, valuePreview, len(cookie.Value))
		}
		if cookie.Name == "_mc_session" && len(cookie.Value) > 100 {
			hasSessionCookie = true
			if debug {
				fmt.Printf("  ✓ This is a valid authenticated session cookie\n")
			}
		}
	}

	if !hasSessionCookie {
		// Print more of the HTML body to see what page we actually got
		preview := loginResp.Body
		if len(preview) > 3000 {
			preview = preview[:3000]
		}
		if strings.Contains(preview, "<title>") {
			titleStart := strings.Index(preview, "<title>") + 7
			titleEnd := strings.Index(preview, "</title>")
			if titleEnd > titleStart {
				fmt.Printf("Page title: %s\n", preview[titleStart:titleEnd])
			}
		}
		return fmt.Errorf("login failed - no valid session cookie received")
	}

	// Extract cookies and save to cookiejar
	// Use the base domain (without www) so cookies work across all subdomains
	masterclassURL, _ := url.Parse("https://masterclass.com")
	edgeURL, _ := url.Parse("https://edge.masterclass.com")

	// Convert CycleTLS cookies to http.Cookie
	// Create NEW cookie objects with proper domain to ensure they work across subdomains
	var cookies []*http.Cookie

	// Collect all cookies from the session
	allCookies := make(map[string]*http.Cookie)

	// Add from home page
	for _, cookie := range homePageResp.Cookies {
		// Create a new cookie with proper domain
		domain := cookie.Domain
		if domain == "" || domain == "masterclass.com" {
			domain = ".masterclass.com" // Leading dot for subdomain sharing
		}
		if !strings.HasPrefix(domain, ".") && strings.Contains(domain, ".") {
			domain = "." + domain
		}
		newCookie := &http.Cookie{
			Name:     cookie.Name,
			Value:    cookie.Value,
			Path:     cookie.Path,
			Domain:   domain,
			Expires:  cookie.Expires,
			Secure:   cookie.Secure,
			HttpOnly: cookie.HttpOnly,
			SameSite: cookie.SameSite,
		}
		if newCookie.Path == "" {
			newCookie.Path = "/"
		}
		allCookies[cookie.Name] = newCookie
	}

	// Update/add from login response (overwrites duplicates)
	for _, cookie := range loginResp.Cookies {
		// Create a new cookie with proper domain
		domain := cookie.Domain
		if domain == "" || domain == "masterclass.com" {
			domain = ".masterclass.com" // Leading dot for subdomain sharing
		}
		if !strings.HasPrefix(domain, ".") && strings.Contains(domain, ".") {
			domain = "." + domain
		}
		newCookie := &http.Cookie{
			Name:     cookie.Name,
			Value:    cookie.Value,
			Path:     cookie.Path,
			Domain:   domain,
			Expires:  cookie.Expires,
			Secure:   cookie.Secure,
			HttpOnly: cookie.HttpOnly,
			SameSite: cookie.SameSite,
		}
		if newCookie.Path == "" {
			newCookie.Path = "/"
		}
		allCookies[cookie.Name] = newCookie
	}

	// Convert map to slice
	for _, cookie := range allCookies {
		cookies = append(cookies, cookie)
	}

	if debug {
		fmt.Printf("Saving %d cookies to jar\n", len(cookies))
		for _, c := range cookies {
			fmt.Printf("  - %s (domain: %s, value length: %d)\n", c.Name, c.Domain, len(c.Value))
		}
	}
	// Set cookies on both URLs to ensure they're available for all subdomains
	client.Jar.SetCookies(masterclassURL, cookies)
	client.Jar.SetCookies(edgeURL, cookies)

	// Build clean cookie string from our collected cookies (no duplicates)
	var cleanCookieStr string
	seenCookies := make(map[string]bool)
	for _, cookie := range cookies {
		if !seenCookies[cookie.Name] {
			if cleanCookieStr != "" {
				cleanCookieStr += "; "
			}
			cleanCookieStr += cookie.Name + "=" + cookie.Value
			seenCookies[cookie.Name] = true
		}
	}

	if debug {
		fmt.Printf("Using %d unique cookies\n", len(seenCookies))
	}

	// No need to visit profiles page - we already have the session cookie

	// Now fetch profiles API
	if debug {
		fmt.Println("Fetching profiles API...")
	}
	req, err := http.NewRequest("GET", "https://www.masterclass.com/jsonapi/v1/profiles?deep=true", nil)
	if err != nil {
		return fmt.Errorf("failed to create profiles request: %v", err)
	}
	req.Header.Set("Cookie", cleanCookieStr)
	req.Header.Set("Referer", "https://www.masterclass.com/profiles")
	req.Header.Set("User-Agent", userAgent)

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to get profiles: %v", err)
	}
	defer resp.Body.Close()

	if debug {
		fmt.Printf("Profiles response status: %d\n", resp.StatusCode)
	}

	if resp.StatusCode != 200 {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("failed to get profiles: status=%d, body=%s", resp.StatusCode, string(body))
	}

	var profiles []ProfileResponse
	err = json.NewDecoder(resp.Body).Decode(&profiles)
	if err != nil {
		return fmt.Errorf("failed to parse profiles: %v", err)
	}

	if len(profiles) == 0 {
		return fmt.Errorf("no profiles found")
	}

	prompt := promptui.Select{
		Label: "Select Profile",
		Items: profiles,
		Templates: &promptui.SelectTemplates{
			Label:    "{{ .DisplayName }}",
			Active:   "\U0001F449 {{ .DisplayName }}",
			Inactive: "  {{ .DisplayName }}",
			Selected: "\U0001F64C {{ .DisplayName }}",
		},
	}

	i, _, err := prompt.Run()
	if err != nil {
		return err
	}
	fmt.Printf("Selected profile: %s\n", profiles[i].DisplayName)

	// Write selected profile to datDir + "/profile.json"
	profileFile, err := os.Create(path.Join(datDir, "profile.json"))
	if err != nil {
		return err
	}
	defer profileFile.Close()
	err = json.NewEncoder(profileFile).Encode(profiles[i])
	if err != nil {
		return err
	}

	return nil
}

func getProfile(client *http.Client, datDir string) (*ProfileResponse, error) {
	profileFile, err := os.Open(path.Join(datDir, "profile.json"))
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("profile not found. Please login first")
		}
		return nil, err
	}
	defer profileFile.Close()
	var profile ProfileResponse
	err = json.NewDecoder(profileFile).Decode(&profile)
	if err != nil {
		return nil, err
	}
	return &profile, nil
}

func loginStatus(client *http.Client, datDir string) error {
	if (client.Jar.Cookies(&url.URL{Scheme: "https", Host: "www.masterclass.com"}) == nil) {
		return fmt.Errorf("cookies not found. Please login first")
	}

	profile, err := getProfile(client, datDir)
	if err != nil {
		return err
	}

	req, err := http.NewRequest("GET", "https://www.masterclass.com/jsonapi/v1/subscriptions/current?include=purchase_plan%2Cpurchase_plan.product%2Crenewal_purchase_plan%2Crenewal_purchase_plan.product", nil)
	req.Header.Set("Mc-Profile-Id", profile.UUID)
	req.Header.Set("Referer", "https://www.masterclass.com/homepage")
	if err != nil {
		return err
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return fmt.Errorf("failed to get subscription status")
	}
	var subscription SubscriptionResponse
	err = json.NewDecoder(resp.Body).Decode(&subscription)
	if err != nil {
		return err
	}

	req, err = http.NewRequest("GET", "https://www.masterclass.com/jsonapi/v1/user/cart-data?deep=true", nil)
	req.Header.Set("Mc-Profile-Id", profile.UUID)
	req.Header.Set("Referer", "https://www.masterclass.com/homepage")
	if err != nil {
		return err
	}
	resp, err = client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return fmt.Errorf("failed to get login status")
	}
	var cartData CartDataResponse
	err = json.NewDecoder(resp.Body).Decode(&cartData)
	if err != nil {
		return err
	}
	fmt.Printf("Email: %s\n", cartData.Email)
	fmt.Printf("Subscription Status: %s\n", subscription.Status)
	fmt.Printf("Subscription Expires At: %s\n", subscription.ExpiresAt)
	fmt.Printf("Subscription Remaining Days: %d\n", subscription.RemainingDays)
	return nil
}

func download(client *http.Client, datDir string, outputDir string, downloadPdfs bool, downloadPosters bool, ytdlExec string, nameAsSeries bool, arg string) error {
	if (client.Jar.Cookies(&url.URL{Scheme: "https", Host: "www.masterclass.com"}) == nil) {
		return fmt.Errorf("cookies not found. Please login first")
	}

	profile, err := getProfile(client, datDir)
	if err != nil {
		return err
	}

	classSlug := ""
	chapterSlug := ""
	if strings.Contains(arg, "/chapters/") {
		classSlug = strings.Split(arg, "/chapters/")[0]
		chapterSlug = strings.Split(arg, "/chapters/")[1]
	} else {
		classSlug = arg
	}

	classSlug = strings.TrimPrefix(classSlug, "https://www.masterclass.com/classes/")
	classSlug = strings.TrimSuffix(classSlug, "/")
	chapterSlug = strings.TrimPrefix(chapterSlug, "https://www.masterclass.com/classes/")
	chapterSlug = strings.TrimSuffix(chapterSlug, "/")
	if classSlug == "" {
		return fmt.Errorf("invalid class slug")
	}

	//get class info
	req, err := http.NewRequest("GET", "https://www.masterclass.com/jsonapi/v1/courses/"+classSlug+"?deep=true", nil)
	req.Header.Set("Referer", "https://www.masterclass.com/classes/"+classSlug)
	req.Header.Set("Mc-Profile-Id", profile.UUID)
	if err != nil {
		return err
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return fmt.Errorf("failed to get class info")
	}
	var class CourseResponse
	err = json.NewDecoder(resp.Body).Decode(&class)
	if err != nil {
		return err
	}

	outputDir = path.Join(outputDir, class.Title)
	err = os.MkdirAll(outputDir, 0755)
	if err != nil {
		return err
	}

	// Download show artwork (Plex naming convention)
	if downloadPosters {
		if class.Primary2x3 != "" {
			fmt.Println("Downloading poster image")
			err = downloadImage(client, class.Primary2x3, path.Join(outputDir, "poster.jpg"))
			if err != nil {
				fmt.Printf("Warning: failed to download poster: %v\n", err)
			}
		}
		if class.Primary16x9 != "" {
			fmt.Println("Downloading fanart image")
			err = downloadImage(client, class.Primary16x9, path.Join(outputDir, "fanart.jpg"))
			if err != nil {
				fmt.Printf("Warning: failed to download fanart: %v\n", err)
			}
		}
	}

	if downloadPdfs {
		fmt.Println("Downloading PDFs")
		for _, pdf := range class.AllPDFs {
			req, err := http.NewRequest("GET", pdf.URL, nil)
			if err != nil {
				return err
			}
			req.Header.Set("Referer", "https://www.masterclass.com/classes/"+classSlug)
			req.Header.Set("Mc-Profile-Id", profile.UUID)
			resp, err := client.Do(req)
			if err != nil {
				return err
			}
			defer resp.Body.Close()
			if resp.StatusCode != 200 {
				return fmt.Errorf("failed to download PDF")
			}
			pdfFile, err := os.Create(path.Join(outputDir, pdf.Title+".pdf"))
			if err != nil {
				return err
			}
			defer pdfFile.Close()
			_, err = io.Copy(pdfFile, resp.Body)
			if err != nil {
				return err
			}
		}
	}

	// Masterclass uses a fixed API key for media metadata requests
	apiKey := "b9517f7d8d1f48c2de88100f2c13e77a9d8e524aed204651acca65202ff5c6cb9244c045795b1fafda617ac5eb0a6c50"
	fmt.Printf("Using API key\n")

	for _, chapter := range class.Chapters {
		if chapterSlug != "" && chapter.Slug != chapterSlug {
			continue
		}
		fmt.Printf("Downloading chapter %d: %s\n", chapter.Number, chapter.Title)
		err := downloadChapter(client, profile.UUID, outputDir, ytdlExec, chapter, class, apiKey, nameAsSeries)
		if err != nil {
			return err
		}
	}

	fmt.Println("Done")

	return nil
}

func downloadCategory(client *http.Client, datDir string, outputDir string, downloadPdfs bool, downloadPosters bool, ytdlExec string, limit int, nameAsSeries bool, arg string) error {
	if (client.Jar.Cookies(&url.URL{Scheme: "https", Host: "www.masterclass.com"}) == nil) {
		return fmt.Errorf("cookies not found. Please login first")
	}

	profile, err := getProfile(client, datDir)
	if err != nil {
		return err
	}

	// Parse the category URL to extract bundle name
	// Input: https://www.masterclass.com/homepage/science-and-tech
	// Bundle: homepage-science-and-tech
	categorySlug := arg
	categorySlug = strings.TrimPrefix(categorySlug, "https://www.masterclass.com/")
	categorySlug = strings.TrimPrefix(categorySlug, "http://www.masterclass.com/")
	categorySlug = strings.TrimSuffix(categorySlug, "/")

	// Convert path to bundle format: homepage/science-and-tech -> homepage-science-and-tech
	bundle := strings.ReplaceAll(categorySlug, "/", "-")

	fmt.Printf("Fetching category: %s (bundle: %s)\n", categorySlug, bundle)

	// Call the content-rows API
	apiURL := fmt.Sprintf("https://www.masterclass.com/jsonapi/v3/content-rows?filter[platform]=web&filter[bundle]=%s&include_items=true", bundle)

	req, err := http.NewRequest("GET", apiURL, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Referer", "https://www.masterclass.com/"+categorySlug)
	req.Header.Set("Mc-Profile-Id", profile.UUID)

	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("failed to get category info: status=%d, body=%s", resp.StatusCode, string(body))
	}

	var contentRows ContentRowsResponse
	err = json.NewDecoder(resp.Body).Decode(&contentRows)
	if err != nil {
		return fmt.Errorf("failed to parse content rows: %v", err)
	}

	// Extract all unique courses from all rows
	type CourseInfo struct {
		Slug     string
		Title    string
		Subtitle string
		Duration string
	}
	courseMap := make(map[string]CourseInfo)
	for _, row := range contentRows {
		for _, item := range row.Items {
			// Only include courses (not series or other content types)
			resource := item.Default.Resource
			if resource.EntitySlug != "" && resource.EntityType == "course" {
				courseMap[resource.EntitySlug] = CourseInfo{
					Slug:     resource.EntitySlug,
					Title:    item.Default.Title,
					Subtitle: item.Default.Subtitle,
					Duration: item.Default.Duration,
				}
			}
		}
	}

	// Convert to slice
	var courses []CourseInfo
	for _, info := range courseMap {
		courses = append(courses, info)
	}

	fmt.Printf("\nFound %d courses in category '%s':\n", len(courses), categorySlug)
	fmt.Println(strings.Repeat("-", 60))

	// Print all courses
	for i, course := range courses {
		duration := ""
		if course.Duration != "" {
			duration = fmt.Sprintf(" (%s)", course.Duration)
		}
		subtitle := ""
		if course.Subtitle != "" {
			subtitle = fmt.Sprintf(" - %s", course.Subtitle)
		}
		fmt.Printf("%3d. %s%s%s\n", i+1, course.Title, subtitle, duration)
	}
	fmt.Println(strings.Repeat("-", 60))

	// Apply limit
	downloadCount := len(courses)
	if limit > 0 && limit < downloadCount {
		downloadCount = limit
		fmt.Printf("\nDownloading first %d of %d courses (use --limit 0 for all):\n\n", downloadCount, len(courses))
	} else {
		fmt.Printf("\nDownloading all %d courses:\n\n", downloadCount)
	}

	// Download each course
	for i := 0; i < downloadCount; i++ {
		course := courses[i]
		fmt.Printf("\n[%d/%d] Downloading: %s\n", i+1, downloadCount, course.Title)
		fmt.Println(strings.Repeat("=", 60))

		err := download(client, datDir, outputDir, downloadPdfs, downloadPosters, ytdlExec, nameAsSeries, course.Slug)
		if err != nil {
			fmt.Printf("Error downloading %s: %v\n", course.Slug, err)
			// Continue with next course instead of stopping
			continue
		}
	}

	fmt.Printf("\n\nCategory download complete! Downloaded %d courses.\n", downloadCount)
	return nil
}

func downloadChapter(client *http.Client, profileUUID string, outputDir string, ytdlExec string, chapter Chapter, course CourseResponse, apiKey string, nameAsSeries bool) error {
	// Use CycleTLS for the media metadata API request to bypass any Cloudflare protection
	cycleclient := cycletls.Init()
	// Don't close cycleclient - it causes a panic and isn't necessary for short-lived processes

	// Build cookie string from jar - try getting from www.masterclass.com
	wwwURL, _ := url.Parse("https://www.masterclass.com")
	edgeURL, _ := url.Parse("https://edge.masterclass.com")

	// Get cookies from both URLs and merge them
	wwwCookies := client.Jar.Cookies(wwwURL)
	edgeCookies := client.Jar.Cookies(edgeURL)

	fmt.Printf("Debug: www cookies: %d, edge cookies: %d\n", len(wwwCookies), len(edgeCookies))

	// Build a map to collect unique cookies, preferring www cookies
	cookieMap := make(map[string]string)
	for _, c := range edgeCookies {
		cookieMap[c.Name] = c.Value
	}
	for _, c := range wwwCookies {
		cookieMap[c.Name] = c.Value // Overwrite with www value if exists
	}

	var cookieStr string
	first := true
	for name, value := range cookieMap {
		if !first {
			cookieStr += "; "
		}
		cookieStr += name + "=" + value
		first = false
	}

	// Debug: show what we're sending
	fmt.Printf("Media metadata request:\n")
	fmt.Printf("  URL: https://edge.masterclass.com/api/v1/media/metadata/%s\n", chapter.MediaUUID)
	fmt.Printf("  Mc-Profile-Id: %s\n", profileUUID)
	fmt.Printf("  X-Api-Key: %s\n", apiKey)
	fmt.Printf("  Cookie header length: %d\n", len(cookieStr))

	metadataResp, err := cycleclient.Do("https://edge.masterclass.com/api/v1/media/metadata/"+chapter.MediaUUID, cycletls.Options{
		Body:      "",
		Ja3:       ja3,
		UserAgent: userAgent,
		Headers: map[string]string{
			"Accept":             "application/json",
			"Accept-Language":    "en-US,en;q=0.9",
			"Content-Type":       "application/json",
			"Origin":             "https://www.masterclass.com",
			"Referer":            "https://www.masterclass.com/",
			"Mc-Profile-Id":      profileUUID,
			"X-Api-Key":          apiKey,
			"Cookie":             cookieStr,
			"Sec-Fetch-Dest":     "empty",
			"Sec-Fetch-Mode":     "cors",
			"Sec-Fetch-Site":     "same-site",
			"Sec-Ch-Ua":          `"Chromium";v="141", "Not?A_Brand";v="8"`,
			"Sec-Ch-Ua-Mobile":   "?0",
			"Sec-Ch-Ua-Platform": `"macOS"`,
		},
	}, "GET")

	if err != nil {
		return fmt.Errorf("failed to fetch metadata: %v", err)
	}

	if metadataResp.Status != 200 {
		fmt.Printf("Response status: %d\n", metadataResp.Status)
		fmt.Printf("Response body: %s\n", metadataResp.Body[:min(len(metadataResp.Body), 500)])
		return fmt.Errorf("failed to get chapter metadata: status=%d", metadataResp.Status)
	}

	var chapterMetadata ChapterMetadataResponse
	err = json.Unmarshal([]byte(metadataResp.Body), &chapterMetadata)
	if err != nil {
		return fmt.Errorf("failed to parse metadata: %v", err)
	}

	// Generate filename based on naming mode
	var baseFileName string
	if nameAsSeries {
		// TV series format: s01e01-Title.mp4 or s01e01-Title-Extra_trailer.mp4
		if chapter.IsExampleLesson {
			baseFileName = fmt.Sprintf("s01e%02d-%s-Extra_trailer", chapter.Number, chapter.Title)
		} else {
			baseFileName = fmt.Sprintf("s01e%02d-%s", chapter.Number, chapter.Title)
		}
	} else {
		// Default format: 001-Title.mp4
		baseFileName = fmt.Sprintf("%03d-%s", chapter.Number, chapter.Title)
	}
	outputFile := path.Join(outputDir, baseFileName+".mp4")

	// Build metadata arguments
	var metadataArgs string
	if nameAsSeries {
		// Extract date (YYYY-MM-DD) from UpdatedAt
		dateStr := ""
		if chapter.UpdatedAt != "" && len(chapter.UpdatedAt) >= 10 {
			dateStr = chapter.UpdatedAt[:10] // "2024-03-20T..." -> "2024-03-20"
		}

		// Get genre from first category
		genre := "Education"
		if len(course.Categories) > 0 {
			genre = course.Categories[0].Name
		}

		// Generate episode_id
		episodeID := fmt.Sprintf("s01e%02d", chapter.Number)

		// Full metadata for series format
		metadataArgs = fmt.Sprintf(
			"ffmpeg:-metadata title=%q -metadata show=%q -metadata artist=%q -metadata genre=%q -metadata date=%q -metadata description=%q -metadata synopsis=%q -metadata season_number=1 -metadata episode_sort=%d -metadata episode_id=%q -metadata network=%q",
			chapter.Title,
			course.Title,
			course.InstructorName,
			genre,
			dateStr,
			chapter.Abstract,
			course.Overview,
			chapter.Number,
			episodeID,
			"MasterClass",
		)
	} else {
		// Basic metadata (original behavior)
		metadataArgs = fmt.Sprintf("ffmpeg:-metadata title=%q -metadata description=%q -metadata episode_sort=%d",
			chapter.Title, chapter.Abstract, chapter.Number)
	}

	// Build yt-dlp command with metadata embedding
	args := []string{
		"--embed-subs", "--all-subs",
		"--embed-metadata",
		"-f", "bestvideo+bestaudio",
		"--postprocessor-args", metadataArgs,
		chapterMetadata.Sources[0].Src,
		"-o", outputFile,
	}

	cmd := exec.Command(ytdlExec, args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	err = cmd.Run()
	if err != nil {
		return err
	}

	return nil
}

func downloadImage(client *http.Client, imageURL string, outputPath string) error {
	resp, err := client.Get(imageURL)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return fmt.Errorf("failed to download image: status=%d", resp.StatusCode)
	}

	file, err := os.Create(outputPath)
	if err != nil {
		return err
	}
	defer file.Close()

	_, err = io.Copy(file, resp.Body)
	return err
}
