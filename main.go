package main

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"encoding/xml"
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
	var writeNfo bool
	var metadataOnly bool
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
			// Log enabled options
			if metadataOnly {
				fmt.Println("--metadata-only specified, downloading poster, fanart, and NFO only (no videos)")
			}
			if writeNfo && !metadataOnly {
				fmt.Println("--write-nfo specified, will write tvshow.nfo file")
			}
			if nameAsSeries {
				fmt.Println("--name-files-as-series specified, will use s01e01 naming format")
			}
			if !downloadPdfs && !metadataOnly {
				fmt.Println("--pdfs=false specified, skipping PDF downloads")
			}
			if !downloadPosters {
				fmt.Println("--posters=false specified, skipping poster/fanart downloads")
			}
			if limit != 10 {
				fmt.Printf("--limit=%d specified for category downloads\n", limit)
			}
			fmt.Println()

			for _, arg := range args {
				// Check if this is a category/homepage URL
				if strings.Contains(arg, "/homepage/") {
					err := downloadCategory(getClient(datDir), datDir, outputDir, downloadPdfs, downloadPosters, ytdlExec, limit, nameAsSeries, writeNfo, metadataOnly, arg)
					if err != nil {
						fmt.Println(err)
					}
				} else {
					err := download(getClient(datDir), datDir, outputDir, downloadPdfs, downloadPosters, ytdlExec, nameAsSeries, writeNfo, metadataOnly, arg)
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
	downloadCmd.Flags().BoolVar(&writeNfo, "write-nfo", false, "Write tvshow.nfo metadata file for Plex/Jellyfin")
	downloadCmd.Flags().BoolVar(&metadataOnly, "metadata-only", false, "Download only metadata (poster, fanart, NFO) - no videos or PDFs")
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

	var jsonOutput bool
	var metadataCmd = &cobra.Command{
		Use:   "metadata [url]",
		Short: "Show metadata for a class from masterclass.com",
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			err := showMetadata(getClient(datDir), datDir, jsonOutput, args[0])
			if err != nil {
				fmt.Println(err)
				return
			}
		},
	}
	metadataCmd.Flags().BoolVar(&jsonOutput, "json", true, "Output as JSON")

	rootCmd.AddCommand(downloadCmd)
	rootCmd.AddCommand(loginCmd)
	rootCmd.AddCommand(loginStatusCmd)
	rootCmd.AddCommand(metadataCmd)

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

func showMetadata(client *http.Client, datDir string, jsonOutput bool, arg string) error {
	if client.Jar.Cookies(&url.URL{Scheme: "https", Host: "www.masterclass.com"}) == nil {
		return fmt.Errorf("cookies not found. Please login first")
	}

	profile, err := getProfile(client, datDir)
	if err != nil {
		return err
	}

	// Check if this is a category/homepage URL
	if strings.Contains(arg, "/homepage/") {
		return showCategoryMetadata(client, profile.UUID, jsonOutput, arg)
	}

	// Parse class slug from URL
	classSlug := arg
	classSlug = strings.TrimPrefix(classSlug, "https://www.masterclass.com/classes/")
	classSlug = strings.TrimPrefix(classSlug, "https://www.masterclass.com/series/")
	classSlug = strings.TrimSuffix(classSlug, "/")
	// Remove any chapter suffix
	if strings.Contains(classSlug, "/chapters/") {
		classSlug = strings.Split(classSlug, "/chapters/")[0]
	}

	if classSlug == "" {
		return fmt.Errorf("invalid class URL")
	}

	return showCourseMetadata(client, profile.UUID, jsonOutput, classSlug)
}

func showCourseMetadata(client *http.Client, profileUUID string, jsonOutput bool, classSlug string) error {
	// Fetch course data
	req, err := http.NewRequest("GET", "https://www.masterclass.com/jsonapi/v1/courses/"+classSlug+"?deep=true&include=instructors,chapters,categories", nil)
	if err != nil {
		return err
	}
	req.Header.Set("Referer", "https://www.masterclass.com/classes/"+classSlug)
	req.Header.Set("Mc-Profile-Id", profileUUID)

	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return fmt.Errorf("failed to get class info: status %d", resp.StatusCode)
	}

	// Read raw response body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	if jsonOutput {
		// Pretty print JSON
		var prettyJSON bytes.Buffer
		err = json.Indent(&prettyJSON, body, "", "  ")
		if err != nil {
			// If can't indent, just print raw
			fmt.Println(string(body))
		} else {
			fmt.Println(prettyJSON.String())
		}
	} else {
		// Parse and show key fields
		var course CourseResponse
		err = json.Unmarshal(body, &course)
		if err != nil {
			return err
		}
		fmt.Printf("Title: %s\n", course.Title)
		fmt.Printf("Skill: %s\n", course.Skill)
		fmt.Printf("Headline: %s\n", course.Headline)
		fmt.Printf("VanityName: %s\n", course.VanityName)
		fmt.Printf("InstructorName: %s\n", course.InstructorName)
		fmt.Printf("Slug: %s\n", course.Slug)
	}

	return nil
}

func showCategoryMetadata(client *http.Client, profileUUID string, jsonOutput bool, arg string) error {
	// Parse the category URL to extract bundle name
	categorySlug := arg
	categorySlug = strings.TrimPrefix(categorySlug, "https://www.masterclass.com/")
	categorySlug = strings.TrimPrefix(categorySlug, "http://www.masterclass.com/")
	categorySlug = strings.TrimSuffix(categorySlug, "/")

	// Convert path to bundle format: homepage/business -> homepage-business
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
	req.Header.Set("Mc-Profile-Id", profileUUID)

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

	// Extract unique course slugs
	courseMap := make(map[string]bool)
	var courseSlugs []string
	for _, row := range contentRows {
		for _, item := range row.Items {
			resource := item.Default.Resource
			if resource.EntitySlug != "" && resource.EntityType == "course" {
				if !courseMap[resource.EntitySlug] {
					courseMap[resource.EntitySlug] = true
					courseSlugs = append(courseSlugs, resource.EntitySlug)
				}
			}
		}
	}

	fmt.Printf("\nFound %d courses in category:\n", len(courseSlugs))
	fmt.Println(strings.Repeat("-", 80))

	if jsonOutput {
		// Output as JSON array of course metadata
		fmt.Println("[")
		for i, slug := range courseSlugs {
			err := showCourseMetadata(client, profileUUID, true, slug)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Warning: failed to get metadata for %s: %v\n", slug, err)
				continue
			}
			if i < len(courseSlugs)-1 {
				fmt.Println(",")
			}
		}
		fmt.Println("]")
	} else {
		// Output as table - fetch all courses first
		type courseInfo struct {
			Slug              string
			Title             string
			Skill             string
			Headline          string
			VanityName        string
			InstructorName    string
			InstructorTagline string
			Type              string
			NumChapters       int
			TotalSeconds      int
		}
		var courses []courseInfo

		for _, slug := range courseSlugs {
			req, err := http.NewRequest("GET", "https://www.masterclass.com/jsonapi/v1/courses/"+slug+"?deep=true&include=instructors,chapters,categories", nil)
			if err != nil {
				continue
			}
			req.Header.Set("Referer", "https://www.masterclass.com/classes/"+slug)
			req.Header.Set("Mc-Profile-Id", profileUUID)

			resp, err := client.Do(req)
			if err != nil {
				continue
			}

			var course CourseResponse
			err = json.NewDecoder(resp.Body).Decode(&course)
			resp.Body.Close()
			if err != nil {
				continue
			}

			courses = append(courses, courseInfo{
				Slug:              course.Slug,
				Title:             course.Title,
				Skill:             course.Skill,
				Headline:          course.Headline,
				VanityName:        course.VanityName,
				InstructorName:    course.InstructorName,
				InstructorTagline: course.InstructorTagline,
				Type:              course.Type,
				NumChapters:       course.NumChapters,
				TotalSeconds:      course.TotalSeconds,
			})
		}

		// Helper to truncate strings
		trunc := func(s string, max int) string {
			if len(s) > max {
				return s[:max-3] + "..."
			}
			return s
		}

		// Print table header
		fmt.Printf("\n%-3s | %-7s | %-45s | %-45s | %-30s | %-8s | %-30s | %-4s | %-6s | %-40s\n",
			"#", "Type", "Title", "Skill", "Headline", "Vanity", "Instructor", "Chap", "Mins", "Slug")
		fmt.Println(strings.Repeat("-", 240))

		// Print rows
		for i, c := range courses {
			fmt.Printf("%-3d | %-7s | %-45s | %-45s | %-30s | %-8s | %-30s | %-4d | %-6d | %-40s\n",
				i+1,
				c.Type,
				trunc(c.Title, 45),
				trunc(c.Skill, 45),
				trunc(c.Headline, 30),
				trunc(c.VanityName, 8),
				trunc(c.InstructorName, 30),
				c.NumChapters,
				c.TotalSeconds/60,
				trunc(c.Slug, 40))
		}
	}

	return nil
}

func download(client *http.Client, datDir string, outputDir string, downloadPdfs bool, downloadPosters bool, ytdlExec string, nameAsSeries bool, writeNfo bool, metadataOnly bool, arg string) error {
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
	classSlug = strings.TrimPrefix(classSlug, "https://www.masterclass.com/series/")
	classSlug = strings.TrimSuffix(classSlug, "/")
	chapterSlug = strings.TrimPrefix(chapterSlug, "https://www.masterclass.com/classes/")
	chapterSlug = strings.TrimPrefix(chapterSlug, "https://www.masterclass.com/series/")
	chapterSlug = strings.TrimSuffix(chapterSlug, "/")
	if classSlug == "" {
		return fmt.Errorf("invalid class slug")
	}

	//get class info (include=instructors,chapters,categories ensures we get full data for series)
	req, err := http.NewRequest("GET", "https://www.masterclass.com/jsonapi/v1/courses/"+classSlug+"?deep=true&include=instructors,chapters,categories", nil)
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
	fmt.Printf("Output directory: %s\n", outputDir)

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
		// Download instructor portraits
		for _, inst := range class.Instructors {
			if inst.Name != "" {
				var portraitURL string
				if inst.HeadshotURL != nil {
					if headshot, ok := inst.HeadshotURL.(string); ok && headshot != "" {
						portraitURL = headshot + "?width=500&height=500&fit=cover&dpr=2"
					}
				}
				// Fallback to poster image if no headshot
				if portraitURL == "" && class.Primary2x3 != "" {
					portraitURL = class.Primary2x3 + "?width=500&height=500&fit=cover&dpr=2"
				}
				if portraitURL != "" {
					filename := sanitizeFilename(inst.Name) + ".jpg"
					fmt.Printf("Downloading portrait: %s\n", inst.Name)
					err = downloadImage(client, portraitURL, path.Join(outputDir, filename))
					if err != nil {
						fmt.Printf("Warning: failed to download portrait for %s: %v\n", inst.Name, err)
					}
				}
			}
		}
	}

	if downloadPdfs && !metadataOnly {
		fmt.Println("Downloading PDFs")
		for _, pdf := range class.AllPDFs {
			pdfURL := pdf.URL
			pdfTitle := pdf.Title

			// If PDF only has ID (common for series), fetch full details
			if pdfURL == "" && pdf.ID > 0 {
				fmt.Printf("Fetching PDF details for ID %d...\n", pdf.ID)
				pdfReq, err := http.NewRequest("GET", fmt.Sprintf("https://www.masterclass.com/jsonapi/v1/pdfs/%d", pdf.ID), nil)
				if err != nil {
					fmt.Printf("Warning: failed to create PDF request: %v\n", err)
					continue
				}
				pdfReq.Header.Set("Referer", "https://www.masterclass.com/classes/"+classSlug)
				pdfReq.Header.Set("Mc-Profile-Id", profile.UUID)
				pdfResp, err := client.Do(pdfReq)
				if err != nil {
					fmt.Printf("Warning: failed to fetch PDF %d: %v\n", pdf.ID, err)
					continue
				}
				if pdfResp.StatusCode == 200 {
					var pdfDetails struct {
						Title string `json:"title"`
						URL   string `json:"url"`
					}
					err = json.NewDecoder(pdfResp.Body).Decode(&pdfDetails)
					pdfResp.Body.Close()
					if err == nil && pdfDetails.URL != "" {
						pdfURL = pdfDetails.URL
						pdfTitle = pdfDetails.Title
					}
				} else {
					pdfResp.Body.Close()
					fmt.Printf("Warning: PDF %d returned status %d\n", pdf.ID, pdfResp.StatusCode)
					continue
				}
			}

			if pdfURL == "" {
				fmt.Printf("Skipping PDF with empty URL: %s\n", pdfTitle)
				continue
			}
			req, err := http.NewRequest("GET", pdfURL, nil)
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
			fmt.Printf("Downloading: %s\n", pdfTitle)
			pdfFile, err := os.Create(path.Join(outputDir, pdfTitle+".pdf"))
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

	// Download videos (skip if metadataOnly)
	if !metadataOnly {
		// Masterclass uses a fixed API key for media metadata requests
		apiKey := "b9517f7d8d1f48c2de88100f2c13e77a9d8e524aed204651acca65202ff5c6cb9244c045795b1fafda617ac5eb0a6c50"
		fmt.Printf("Using API key\n")

		for _, chapter := range class.Chapters {
			if chapterSlug != "" && chapter.Slug != chapterSlug {
				continue
			}
			fmt.Printf("Downloading chapter %d: %s\n", chapter.Number, chapter.Title)
			err := downloadChapter(client, profile.UUID, outputDir, ytdlExec, chapter, class, apiKey, nameAsSeries, writeNfo)
			if err != nil {
				return err
			}
		}
	}

	// Write NFO metadata file (always write if metadataOnly, otherwise respect writeNfo flag)
	if writeNfo || metadataOnly {
		fmt.Println("Writing tvshow.nfo")
		err = writeNFO(class, outputDir)
		if err != nil {
			fmt.Printf("Warning: failed to write NFO: %v\n", err)
		}

		// Write episode NFOs when in metadata-only mode
		if metadataOnly {
			fmt.Println("Writing episode NFO files")
			for _, chapter := range class.Chapters {
				if chapterSlug != "" && chapter.Slug != chapterSlug {
					continue
				}
				// Generate filename matching video naming convention
				var baseFileName string
				if nameAsSeries {
					if chapter.IsExampleLesson {
						baseFileName = fmt.Sprintf("s01e%02d-%s-Extra_trailer", chapter.Number, chapter.Title)
					} else {
						baseFileName = fmt.Sprintf("s01e%02d-%s", chapter.Number, chapter.Title)
					}
				} else {
					baseFileName = fmt.Sprintf("%03d-%s", chapter.Number, chapter.Title)
				}
				nfoFilename := baseFileName + ".nfo"
				err = writeEpisodeNFO(chapter, class, outputDir, nfoFilename)
				if err != nil {
					fmt.Printf("Warning: failed to write episode NFO for %s: %v\n", chapter.Title, err)
				}
			}
		}
	}

	fmt.Println("Done")

	return nil
}

func downloadCategory(client *http.Client, datDir string, outputDir string, downloadPdfs bool, downloadPosters bool, ytdlExec string, limit int, nameAsSeries bool, writeNfo bool, metadataOnly bool, arg string) error {
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

		err := download(client, datDir, outputDir, downloadPdfs, downloadPosters, ytdlExec, nameAsSeries, writeNfo, metadataOnly, course.Slug)
		if err != nil {
			fmt.Printf("Error downloading %s: %v\n", course.Slug, err)
			// Continue with next course instead of stopping
			continue
		}
	}

	fmt.Printf("\n\nCategory download complete! Downloaded %d courses.\n", downloadCount)
	return nil
}

func downloadChapter(client *http.Client, profileUUID string, outputDir string, ytdlExec string, chapter Chapter, course CourseResponse, apiKey string, nameAsSeries bool, writeNfo bool) error {
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

	// Build metadata arguments - always embed full metadata regardless of naming mode
	// Extract date (YYYY-MM-DD) from UpdatedAt
	dateStr := ""
	if chapter.UpdatedAt != "" && len(chapter.UpdatedAt) >= 10 {
		dateStr = chapter.UpdatedAt[:10] // "2024-03-20T..." -> "2024-03-20"
	}

	// Build genre/tags from all categories
	genre := "Education"
	if len(course.Categories) > 0 {
		var genres []string
		for _, cat := range course.Categories {
			genres = append(genres, cat.Name)
		}
		genre = strings.Join(genres, ", ")
	}

	// Generate episode_id
	episodeID := fmt.Sprintf("s01e%02d", chapter.Number)

	// Full metadata for all downloads
	// Include multiple description tags for compatibility (description, comment, long_description, synopsis)
	metadataArgs := fmt.Sprintf(
		"ffmpeg:-metadata title=%q -metadata show=%q -metadata artist=%q -metadata genre=%q -metadata date=%q -metadata description=%q -metadata comment=%q -metadata long_description=%q -metadata synopsis=%q -metadata season_number=1 -metadata episode_sort=%d -metadata episode_id=%q -metadata network=%q",
		chapter.Title,
		course.Title,
		course.InstructorName,
		genre,
		dateStr,
		chapter.Abstract,
		chapter.Abstract,
		chapter.Abstract,
		course.Overview,
		chapter.Number,
		episodeID,
		"MasterClass",
	)

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

	// Write episode NFO if requested
	if writeNfo {
		nfoFilename := baseFileName + ".nfo"
		err = writeEpisodeNFO(chapter, course, outputDir, nfoFilename)
		if err != nil {
			fmt.Printf("Warning: failed to write episode NFO: %v\n", err)
		}
	}

	return nil
}

// sanitizeFilename removes or replaces characters that are invalid in filenames
func sanitizeFilename(name string) string {
	// Replace problematic characters
	replacer := strings.NewReplacer(
		"/", "-",
		"\\", "-",
		":", "-",
		"*", "",
		"?", "",
		"\"", "",
		"<", "",
		">", "",
		"|", "",
	)
	return replacer.Replace(name)
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

// NFO XML structures for Kodi/Plex/Jellyfin compatibility
type TVShowNFO struct {
	XMLName   xml.Name    `xml:"tvshow"`
	Title     string      `xml:"title"`
	Plot      string      `xml:"plot"`
	Outline   string      `xml:"outline,omitempty"`
	Tagline   string      `xml:"tagline,omitempty"`
	Genres    []string    `xml:"genre"`
	Tags      []string    `xml:"tag,omitempty"`
	Studio    string      `xml:"studio"`
	Premiered string      `xml:"premiered,omitempty"`
	Runtime   int         `xml:"runtime,omitempty"`
	Actors    []NFOActor  `xml:"actor"`
	Thumbs    []NFOThumb  `xml:"thumb"`
	UniqueID  NFOUniqueID `xml:"uniqueid"`
}

type NFOActor struct {
	Name  string `xml:"name"`
	Role  string `xml:"role"`
	Thumb string `xml:"thumb,omitempty"`
	Bio   string `xml:"biography,omitempty"`
}

type NFOThumb struct {
	Aspect string `xml:"aspect,attr"`
	Value  string `xml:",chardata"`
}

type NFOUniqueID struct {
	Type    string `xml:"type,attr"`
	Default bool   `xml:"default,attr"`
	Value   string `xml:",chardata"`
}

// EpisodeNFO represents the episodedetails.nfo format for Kodi/Plex/Jellyfin
type EpisodeNFO struct {
	XMLName   xml.Name    `xml:"episodedetails"`
	Title     string      `xml:"title"`
	ShowTitle string      `xml:"showtitle,omitempty"`
	Season    int         `xml:"season"`
	Episode   int         `xml:"episode"`
	Plot      string      `xml:"plot"`
	Aired     string      `xml:"aired,omitempty"`
	Runtime   int         `xml:"runtime,omitempty"`
	Director  string      `xml:"director,omitempty"`
	Studio    string      `xml:"studio,omitempty"`
	UniqueID  NFOUniqueID `xml:"uniqueid"`
}

// splitInstructorNames splits an instructor string into individual names.
// Handles patterns like:
//   - "Kim Kardashian" -> ["Kim Kardashian"]
//   - "Mike Cessario and Laura Modi" -> ["Mike Cessario", "Laura Modi"]
//   - "Jeff Goodby & Rich Silverstein" -> ["Jeff Goodby", "Rich Silverstein"]
//   - "Rich Paul, Bob Myers, and Draymond Green" -> ["Rich Paul", "Bob Myers", "Draymond Green"]
func splitInstructorNames(instructorStr string) []string {
	var names []string

	// First split by comma
	parts := strings.Split(instructorStr, ",")

	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}

		// Remove leading "and " if present (from "A, B, and C" pattern)
		part = strings.TrimPrefix(part, "and ")
		part = strings.TrimSpace(part)

		// Check for " and " within the part
		if strings.Contains(part, " and ") {
			subParts := strings.Split(part, " and ")
			for _, sp := range subParts {
				sp = strings.TrimSpace(sp)
				if sp != "" {
					names = append(names, sp)
				}
			}
			continue
		}

		// Check for " & " within the part
		if strings.Contains(part, " & ") {
			subParts := strings.Split(part, " & ")
			for _, sp := range subParts {
				sp = strings.TrimSpace(sp)
				if sp != "" {
					names = append(names, sp)
				}
			}
			continue
		}

		// Single name
		if part != "" {
			names = append(names, part)
		}
	}

	return names
}

func writeNFO(course CourseResponse, outputDir string) error {
	nfoPath := path.Join(outputDir, "tvshow.nfo")

	// Extract premiered date (YYYY-MM-DD) from UpdatedAt
	premiered := ""
	if course.UpdatedAt != "" && len(course.UpdatedAt) >= 10 {
		premiered = course.UpdatedAt[:10]
	}

	// Build genres from categories (skip empty names - series only have IDs)
	var genres []string
	for _, cat := range course.Categories {
		if cat.Name != "" {
			genres = append(genres, cat.Name)
		}
	}

	// Note: <tag> in NFO becomes Collections in Plex (via XBMCnfoTVImporter)
	// Use primary category as the tag (e.g., "Business") for collection grouping
	var tags []string
	if course.PrimaryCategory.ID != 0 {
		// Find the primary category name from categories array
		for _, cat := range course.Categories {
			if cat.ID == course.PrimaryCategory.ID && cat.Name != "" {
				tags = append(tags, cat.Name)
				break
			}
		}
	}

	// Build actor list from instructors array (if names populated) or fall back to splitting instructor_name
	var actors []NFOActor
	hasValidInstructors := false
	if len(course.Instructors) > 0 && course.Instructors[0].Name != "" {
		hasValidInstructors = true
		for _, inst := range course.Instructors {
			actor := NFOActor{
				Name: inst.Name,
				Role: "Instructor",
			}
			// Add bio if available
			if inst.Bio != nil {
				if bio, ok := inst.Bio.(string); ok && bio != "" {
					actor.Bio = bio
				}
			}
			// Add headshot URL (Plex/Kodi need full URL, not local filename)
			if inst.HeadshotURL != nil {
				if headshot, ok := inst.HeadshotURL.(string); ok && headshot != "" {
					actor.Thumb = headshot + "?width=500&height=500&fit=cover&dpr=2"
				}
			}
			// Fallback to poster image if no headshot
			if actor.Thumb == "" && course.Primary2x3 != "" {
				actor.Thumb = course.Primary2x3 + "?width=500&height=500&fit=cover&dpr=2"
			}
			actors = append(actors, actor)
		}
	}
	if !hasValidInstructors {
		// Fallback: split instructor_name string
		instructorNames := splitInstructorNames(course.InstructorName)
		for _, name := range instructorNames {
			actor := NFOActor{
				Name: name,
				Role: "Instructor",
			}
			// Use poster as fallback for actor thumb
			if course.Primary2x3 != "" {
				actor.Thumb = course.Primary2x3 + "?width=500&height=500&fit=cover&dpr=2"
			}
			actors = append(actors, actor)
		}
	}

	// Build the NFO struct
	nfo := TVShowNFO{
		Title:     course.Title,
		Plot:      course.Overview,
		Outline:   course.ShortOverview,
		Tagline:   course.InstructorTagline,
		Genres:    genres,
		Tags:      tags,
		Studio:    "MasterClass",
		Premiered: premiered,
		Runtime:   course.TotalSeconds / 60,
		Actors:    actors,
		Thumbs: []NFOThumb{
			{Aspect: "poster", Value: "poster.jpg"},
			{Aspect: "fanart", Value: "fanart.jpg"},
		},
		UniqueID: NFOUniqueID{
			Type:    "masterclass",
			Default: true,
			Value:   course.Slug,
		},
	}

	// Marshal to XML with indentation
	output, err := xml.MarshalIndent(nfo, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal NFO: %v", err)
	}

	// Add XML declaration
	xmlContent := []byte(xml.Header + string(output) + "\n")

	return os.WriteFile(nfoPath, xmlContent, 0644)
}

// writeEpisodeNFO writes an episodedetails.nfo file for a single episode
func writeEpisodeNFO(chapter Chapter, course CourseResponse, outputDir string, nfoFilename string) error {
	nfoPath := path.Join(outputDir, nfoFilename)

	// Extract aired date from chapter's UpdatedAt (YYYY-MM-DD)
	aired := ""
	if chapter.UpdatedAt != "" && len(chapter.UpdatedAt) >= 10 {
		aired = chapter.UpdatedAt[:10]
	}

	// Calculate runtime in minutes from DurationSecs
	runtime := 0
	if chapter.DurationSecs > 0 {
		runtime = chapter.DurationSecs / 60
	}

	nfo := EpisodeNFO{
		Title:     chapter.Title,
		ShowTitle: course.Title,
		Season:    1,
		Episode:   chapter.Number,
		Plot:      chapter.Abstract,
		Aired:     aired,
		Runtime:   runtime,
		Director:  course.InstructorName,
		Studio:    "MasterClass",
		UniqueID: NFOUniqueID{
			Type:    "masterclass",
			Default: true,
			Value:   chapter.Slug,
		},
	}

	// Marshal to XML with indentation
	output, err := xml.MarshalIndent(nfo, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal episode NFO: %v", err)
	}

	// Add XML declaration
	xmlContent := []byte(xml.Header + string(output) + "\n")

	return os.WriteFile(nfoPath, xmlContent, 0644)
}
