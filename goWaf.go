package main

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

var backendProxy *httputil.ReverseProxy

var (
	logFile   *os.File
	csvWriter *csv.Writer
	logMutex  sync.Mutex
)

type FeatureVector struct {
	URLLength        float64 `json:"url_length"`
	PathLength       float64 `json:"path_length"`
	QueryLength      float64 `json:"query_length"`
	NumParams        float64 `json:"num_params"`
	NumQuotes        float64 `json:"num_quotes"`
	BodyLength       float64 `json:"body_length"`
	NumPercent       float64 `json:"num_percent"`
	NumSemicolons    float64 `json:"num_semicolons"`
	NumDashes        float64 `json:"num_dashes"`
	NumSlashes       float64 `json:"num_slashes"`
	NumDots          float64 `json:"num_dots"`
	HasSQLKeywords   float64 `json:"has_sql_keywords"`
	HasXSSKeywords   float64 `json:"has_xss_keywords"`
	HasPathTraversal float64 `json:"has_path_traversal"`
	HeaderCount      float64 `json:"header_count"`
	MethodGET        float64 `json:"method_get"`
	MethodPOST       float64 `json:"method_post"` // ← FIXED: was json:"json:"method_post""
}

type MLResponse struct {
	IsAttack   bool    `json:"is_attack"`
	Cluster    int     `json:"cluster"`
	Confidence float64 `json:"confidence"`
}

func extractFeatures(r *http.Request) FeatureVector {
	fullURL := r.URL.String()
	path := r.URL.Path
	query := r.URL.RawQuery

	var bodyLength float64
	if r.Body != nil {
		bodyBytes, _ := io.ReadAll(r.Body)
		bodyLength = float64(len(bodyBytes))
		r.Body = io.NopCloser(bytes.NewReader(bodyBytes))
	}

	// One-hot encode HTTP method
	var methodGET, methodPOST float64
	if r.Method == "GET" {
		methodGET = 1.0
	} else if r.Method == "POST" {
		methodPOST = 1.0
	}

	return FeatureVector{
		URLLength:        float64(len(fullURL)),
		PathLength:       float64(len(path)),
		QueryLength:      float64(len(query)),
		NumParams:        float64(len(r.URL.Query())),
		NumQuotes:        float64(strings.Count(fullURL, "'") + strings.Count(fullURL, `"`)),
		BodyLength:       bodyLength,
		NumPercent:       float64(strings.Count(fullURL, "%")),
		NumSemicolons:    float64(strings.Count(fullURL, ";")),
		NumDashes:        float64(strings.Count(fullURL, "-")),
		NumSlashes:       float64(strings.Count(path, "/")),
		NumDots:          float64(strings.Count(path, ".")),
		HasSQLKeywords:   boolToFloat(hasSQLKeywords(fullURL+query)),
		HasXSSKeywords:   boolToFloat(hasXSSKeywords(fullURL+query)),
		HasPathTraversal: boolToFloat(hasPathTraversal(fullURL)),
		HeaderCount:      float64(len(r.Header)),
		MethodGET:        methodGET,
		MethodPOST:       methodPOST,
	}
}

func hasSQLKeywords(s string) bool {
	re := regexp.MustCompile(`(?i)\b(select|union|insert|delete|drop|update|where|from|or\s+1\s*=\s*1|and\s+1\s*=\s*1)\b`)
	return re.MatchString(s)
}

func hasXSSKeywords(s string) bool {
	re := regexp.MustCompile(`(?i)(<script|javascript:|onerror=|onload=|alert\(|confirm\(|prompt\()`)
	return re.MatchString(s)
}

func hasPathTraversal(s string) bool {
	return strings.Contains(s, "../") || strings.Contains(s, `..\`)
}

func boolToFloat(b bool) float64 {
	if b {
		return 1.0
	}
	return 0.0
}

func MLapiPy(feature FeatureVector) (MLResponse, error) {
	jsonData, err := json.Marshal(feature)
	if err != nil {
		return MLResponse{IsAttack: true, Confidence: 1.0}, err // ← FAIL-CLOSED
	}

	client := &http.Client{Timeout: 2 * time.Second}
	resp, err := client.Post("http://localhost:8000/predict", "application/json", bytes.NewBuffer(jsonData)) // ← FIXED: port 8000
	if err != nil {
		return MLResponse{IsAttack: true, Confidence: 1.0}, err // ← FAIL-CLOSED
	}
	defer resp.Body.Close()

	var response MLResponse
	err = json.NewDecoder(resp.Body).Decode(&response)
	if err != nil {
		return MLResponse{IsAttack: true, Confidence: 1.0}, err // ← FAIL-CLOSED
	}
	return response, nil
}

func wafHandler(w http.ResponseWriter, r *http.Request) {
	features := extractFeatures(r)

	mlres, err := MLapiPy(features)
	if err != nil {
		log.Printf("🚨 WAF ML Service unavailable: %v", err)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusServiceUnavailable)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"error": "Security verification unavailable. Please try again later.",
		})
		return
	}

	// ← CRITICAL: Log the request BEFORE making the decision
	logRequest(r, features, mlres)

	if mlres.Confidence > 0.7 && mlres.IsAttack {
		log.Printf("🚫 BLOCKED! ATTACK INTERCEPTED! (confidence: %.2f)", mlres.Confidence)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"error":      "Attack detected and blocked by ML-WAF",
			"confidence": mlres.Confidence,
		})
		return
	}

	log.Printf("✅ ALLOWED (confidence: %.2f)", mlres.Confidence)
	backendProxy.ServeHTTP(w, r)
}

func logRequest(r *http.Request, feature FeatureVector, mlresp MLResponse) {
	record := []string{
		time.Now().Format(time.RFC3339),
		r.RemoteAddr,
		r.Method,
		r.URL.String(),
		strconv.FormatFloat(feature.URLLength, 'f', 2, 64),
		strconv.FormatFloat(feature.PathLength, 'f', 2, 64),
		strconv.FormatFloat(feature.QueryLength, 'f', 2, 64),
		strconv.FormatFloat(feature.NumParams, 'f', 0, 64),
		strconv.FormatFloat(feature.NumQuotes, 'f', 0, 64),
		strconv.FormatFloat(feature.NumPercent, 'f', 0, 64),
		strconv.FormatFloat(feature.NumSemicolons, 'f', 0, 64),
		strconv.FormatFloat(feature.NumDashes, 'f', 0, 64),
		strconv.FormatFloat(feature.NumSlashes, 'f', 0, 64),
		strconv.FormatFloat(feature.NumDots, 'f', 0, 64),
		strconv.FormatFloat(feature.HasSQLKeywords, 'f', 0, 64),
		strconv.FormatFloat(feature.HasXSSKeywords, 'f', 0, 64),
		strconv.FormatFloat(feature.HasPathTraversal, 'f', 0, 64),
		strconv.FormatFloat(feature.BodyLength, 'f', 2, 64),
		strconv.FormatFloat(feature.HeaderCount, 'f', 0, 64),
		strconv.FormatFloat(feature.MethodGET, 'f', 0, 64),
		strconv.FormatFloat(feature.MethodPOST, 'f', 0, 64),
		strconv.FormatFloat(boolToFloat(mlresp.IsAttack), 'f', 0, 64),
		strconv.FormatFloat(mlresp.Confidence, 'f', 4, 64),
	}

	logMutex.Lock()
	defer logMutex.Unlock()

	csvWriter.Write(record)
	csvWriter.Flush()
}

func init() {
	// 1. Setup backend proxy
	backendURL, _ := url.Parse("http://localhost:3000")
	backendProxy = httputil.NewSingleHostReverseProxy(backendURL)

	// 2. Setup CSV logger ← THIS WAS MISSING!
	var err error
	logFile, err = os.OpenFile("waf_logs.csv", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Fatal("Failed to open waf_logs.csv:", err)
	}
	csvWriter = csv.NewWriter(logFile)

	// Write headers if file is new
	fileInfo, _ := logFile.Stat()
	if fileInfo.Size() == 0 {
		headers := []string{
			"timestamp", "client_ip", "method", "url",
			"url_length", "path_length", "query_length", "num_params",
			"num_quotes", "num_percent", "num_semicolons", "num_dashes",
			"num_slashes", "num_dots", "has_sql_keywords", "has_xss_keywords",
			"has_path_traversal", "body_length", "header_count",
			"method_get", "method_post", "is_attack", "confidence",
		}
		csvWriter.Write(headers)
		csvWriter.Flush()
	}
}

func main() {
	http.HandleFunc("/", wafHandler)
	log.Println("🛡️  WAF starting on http://localhost:8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}