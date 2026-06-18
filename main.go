package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

type FilePermissionResponse struct {
	FilePath       string             `json:"file_path"`
	FileName       string             `json:"file_name"`
	Exists         bool               `json:"exists"`
	IsExecutable   bool               `json:"is_executable"`
	IsReadable     bool               `json:"is_readable"`
	IsWritable     bool               `json:"is_writable"`
	Size           int64              `json:"size"`
	Permission     string             `json:"permission"`
	IsDir          bool               `json:"is_dir"`
	OS             string             `json:"os"`
	ExecutableInfo string             `json:"executable_info"`
	Hashes         *FileHashResult    `json:"hashes,omitempty"`
	HashVerified   bool               `json:"hash_verified"`
	HashResults    []HashVerifyResult `json:"hash_results,omitempty"`
	IsTampered     bool               `json:"is_tampered"`
	Error          string             `json:"error,omitempty"`
}

type CheckRequest struct {
	FilePath       string        `json:"file_path"`
	ComputeHash    bool          `json:"compute_hash,omitempty"`
	VerifyHash     bool          `json:"verify_hash,omitempty"`
	HashAlgorithm  HashAlgorithm `json:"hash_algorithm,omitempty"`
}

type HashAddRequest struct {
	FilePath    string        `json:"file_path"`
	Algorithm   HashAlgorithm `json:"algorithm"`
	HashValue   string        `json:"hash_value,omitempty"`
	AutoCompute bool          `json:"auto_compute,omitempty"`
	Description string        `json:"description,omitempty"`
}

type HashDeleteRequest struct {
	FilePath  string        `json:"file_path"`
	Algorithm HashAlgorithm `json:"algorithm"`
}

type ApiResponse struct {
	Success bool        `json:"success"`
	Message string      `json:"message,omitempty"`
	Data    interface{} `json:"data,omitempty"`
	Error   string      `json:"error,omitempty"`
}

func writeJSON(w http.ResponseWriter, statusCode int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
	w.WriteHeader(statusCode)
	json.NewEncoder(w).Encode(data)
}

func handleCORS(w http.ResponseWriter, r *http.Request) bool {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusOK)
		return true
	}
	return false
}

func checkPermissions(req CheckRequest) FilePermissionResponse {
	resp := FilePermissionResponse{
		FilePath: req.FilePath,
		OS:       getOSName(),
	}

	absPath, err := filepath.Abs(req.FilePath)
	if err == nil {
		resp.FilePath = absPath
	}

	resp.FileName = filepath.Base(resp.FilePath)

	info, err := os.Stat(resp.FilePath)
	if err != nil {
		if os.IsNotExist(err) {
			resp.Exists = false
			resp.Error = "file does not exist"
			return resp
		}
		resp.Exists = false
		resp.Error = fmt.Sprintf("stat error: %v", err)
		return resp
	}

	resp.Exists = true
	resp.IsDir = info.IsDir()
	resp.Size = info.Size()
	resp.Permission = info.Mode().Perm().String()

	resp.IsReadable = isReadable(resp.FilePath, info)
	resp.IsWritable = isWritable(resp.FilePath, info)

	isExe, infoMsg := isExecutable(resp.FilePath, info)
	resp.IsExecutable = isExe
	resp.ExecutableInfo = infoMsg

	if !resp.IsDir && (req.ComputeHash || req.VerifyHash) {
		algorithm := req.HashAlgorithm
		if algorithm == "" {
			algorithm = HashSHA256
		}

		if req.ComputeHash {
			hashes, hashErr := ComputeAllHashes(resp.FilePath)
			if hashErr != nil {
				resp.Error = fmt.Sprintf("hash computation failed: %v", hashErr)
			} else {
				resp.Hashes = hashes
			}
		}

		if req.VerifyHash {
			standardEntries := GetAllStandardHashesForFile(resp.FilePath)
			resp.HashResults = make([]HashVerifyResult, 0)
			resp.HashVerified = len(standardEntries) > 0

			if len(standardEntries) > 0 {
				currentHashes := resp.Hashes
				if currentHashes == nil {
					currentHashes, _ = ComputeAllHashes(resp.FilePath)
					if currentHashes != nil {
						resp.Hashes = currentHashes
					}
				}

				for _, entry := range standardEntries {
					if currentHashes != nil {
						currentHash := GetHashByAlgorithm(currentHashes, entry.Algorithm)
						isMatch := currentHash == entry.HashValue
						verifyResult := HashVerifyResult{
							Algorithm:    entry.Algorithm,
							CurrentHash:  currentHash,
							ExpectedHash: entry.HashValue,
							IsMatch:      isMatch,
							IsTampered:   !isMatch,
						}
						resp.HashResults = append(resp.HashResults, verifyResult)
						if !isMatch {
							resp.IsTampered = true
						}
					}
				}
			} else {
				singleStandard, found := GetStandardHash(resp.FilePath, algorithm)
				if found {
					verifyResult, vErr := VerifyFileHash(resp.FilePath, algorithm, singleStandard.HashValue)
					if vErr == nil {
						resp.HashResults = append(resp.HashResults, *verifyResult)
						resp.HashVerified = true
						resp.IsTampered = verifyResult.IsTampered
						if resp.Hashes == nil {
							resp.Hashes = &FileHashResult{}
							switch algorithm {
							case HashMD5:
								resp.Hashes.MD5 = verifyResult.CurrentHash
							case HashSHA1:
								resp.Hashes.SHA1 = verifyResult.CurrentHash
							case HashSHA256:
								resp.Hashes.SHA256 = verifyResult.CurrentHash
							case HashSHA512:
								resp.Hashes.SHA512 = verifyResult.CurrentHash
							}
						}
					}
				}
			}
		}
	}

	return resp
}

func checkHandler(w http.ResponseWriter, r *http.Request) {
	if handleCORS(w, r) {
		return
	}

	var req CheckRequest

	if r.Method == http.MethodPost {
		decoder := json.NewDecoder(r.Body)
		if err := decoder.Decode(&req); err != nil {
			writeJSON(w, http.StatusBadRequest, ApiResponse{
				Success: false,
				Error:   fmt.Sprintf("invalid request body: %v", err),
			})
			return
		}
	} else if r.Method == http.MethodGet {
		req.FilePath = r.URL.Query().Get("path")
		if r.URL.Query().Get("compute_hash") == "true" || r.URL.Query().Get("compute_hash") == "1" {
			req.ComputeHash = true
		}
		if r.URL.Query().Get("verify_hash") == "true" || r.URL.Query().Get("verify_hash") == "1" {
			req.VerifyHash = true
		}
		algo := r.URL.Query().Get("algorithm")
		if algo != "" {
			req.HashAlgorithm = HashAlgorithm(strings.ToLower(algo))
		}
	} else {
		writeJSON(w, http.StatusMethodNotAllowed, ApiResponse{
			Success: false,
			Error:   "method not allowed",
		})
		return
	}

	if req.FilePath == "" {
		writeJSON(w, http.StatusBadRequest, ApiResponse{
			Success: false,
			Error:   "file_path parameter is required",
		})
		return
	}

	result := checkPermissions(req)
	writeJSON(w, http.StatusOK, ApiResponse{
		Success: true,
		Data:    result,
	})
}

func hashListHandler(w http.ResponseWriter, r *http.Request) {
	if handleCORS(w, r) {
		return
	}

	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, ApiResponse{
			Success: false,
			Error:   "method not allowed, use GET",
		})
		return
	}

	filePath := r.URL.Query().Get("path")
	var entries []StandardHashEntry
	if filePath != "" {
		entries = GetAllStandardHashesForFile(filePath)
	} else {
		entries = ListAllStandardHashes()
	}

	writeJSON(w, http.StatusOK, ApiResponse{
		Success: true,
		Data: map[string]interface{}{
			"total": len(entries),
			"items": entries,
		},
	})
}

func hashAddHandler(w http.ResponseWriter, r *http.Request) {
	if handleCORS(w, r) {
		return
	}

	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, ApiResponse{
			Success: false,
			Error:   "method not allowed, use POST",
		})
		return
	}

	var req HashAddRequest
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, ApiResponse{
			Success: false,
			Error:   fmt.Sprintf("invalid request body: %v", err),
		})
		return
	}

	if req.FilePath == "" {
		writeJSON(w, http.StatusBadRequest, ApiResponse{
			Success: false,
			Error:   "file_path is required",
		})
		return
	}
	if req.Algorithm == "" {
		req.Algorithm = HashSHA256
	}

	var entry *StandardHashEntry
	var err error

	if req.AutoCompute {
		entry, err = ComputeAndAddStandardHash(req.FilePath, req.Algorithm, req.Description)
	} else {
		if req.HashValue == "" {
			writeJSON(w, http.StatusBadRequest, ApiResponse{
				Success: false,
				Error:   "hash_value is required when auto_compute is false",
			})
			return
		}
		entry, err = AddStandardHash(req.FilePath, req.Algorithm, req.HashValue, req.Description)
	}

	if err != nil {
		writeJSON(w, http.StatusInternalServerError, ApiResponse{
			Success: false,
			Error:   fmt.Sprintf("failed to add hash: %v", err),
		})
		return
	}

	writeJSON(w, http.StatusOK, ApiResponse{
		Success: true,
		Message: "standard hash added successfully",
		Data:    entry,
	})
}

func hashDeleteHandler(w http.ResponseWriter, r *http.Request) {
	if handleCORS(w, r) {
		return
	}

	if r.Method != http.MethodDelete && r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, ApiResponse{
			Success: false,
			Error:   "method not allowed, use DELETE or POST",
		})
		return
	}

	var req HashDeleteRequest
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, ApiResponse{
			Success: false,
			Error:   fmt.Sprintf("invalid request body: %v", err),
		})
		return
	}

	if req.FilePath == "" {
		writeJSON(w, http.StatusBadRequest, ApiResponse{
			Success: false,
			Error:   "file_path is required",
		})
		return
	}
	if req.Algorithm == "" {
		req.Algorithm = HashSHA256
	}

	deleted := DeleteStandardHash(req.FilePath, req.Algorithm)
	if !deleted {
		writeJSON(w, http.StatusNotFound, ApiResponse{
			Success: false,
			Error:   "standard hash not found",
		})
		return
	}

	writeJSON(w, http.StatusOK, ApiResponse{
		Success: true,
		Message: "standard hash deleted successfully",
	})
}

func hashComputeHandler(w http.ResponseWriter, r *http.Request) {
	if handleCORS(w, r) {
		return
	}

	var filePath string
	var algorithm HashAlgorithm

	if r.Method == http.MethodPost {
		var req CheckRequest
		decoder := json.NewDecoder(r.Body)
		if err := decoder.Decode(&req); err != nil {
			writeJSON(w, http.StatusBadRequest, ApiResponse{
				Success: false,
				Error:   fmt.Sprintf("invalid request body: %v", err),
			})
			return
		}
		filePath = req.FilePath
		algorithm = req.HashAlgorithm
	} else if r.Method == http.MethodGet {
		filePath = r.URL.Query().Get("path")
		algo := r.URL.Query().Get("algorithm")
		if algo != "" {
			algorithm = HashAlgorithm(strings.ToLower(algo))
		}
	} else {
		writeJSON(w, http.StatusMethodNotAllowed, ApiResponse{
			Success: false,
			Error:   "method not allowed",
		})
		return
	}

	if filePath == "" {
		writeJSON(w, http.StatusBadRequest, ApiResponse{
			Success: false,
			Error:   "path parameter is required",
		})
		return
	}

	var result interface{}
	var err error

	if algorithm == "" {
		result, err = ComputeAllHashes(filePath)
	} else {
		var hashStr string
		hashStr, err = ComputeFileHash(filePath, algorithm)
		if err == nil {
			result = map[string]string{
				string(algorithm): hashStr,
			}
		}
	}

	if err != nil {
		writeJSON(w, http.StatusInternalServerError, ApiResponse{
			Success: false,
			Error:   fmt.Sprintf("hash computation failed: %v", err),
		})
		return
	}

	writeJSON(w, http.StatusOK, ApiResponse{
		Success: true,
		Data:    result,
	})
}

func healthHandler(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, ApiResponse{
		Success: true,
		Data: map[string]interface{}{
			"status":  "ok",
			"os":      runtime.GOOS,
			"arch":    runtime.GOARCH,
			"version": runtime.Version(),
		},
	})
}

func main() {
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	if err := LoadHashConfig(); err != nil {
		fmt.Fprintf(os.Stderr, "Warning: failed to load hash config: %v\n", err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/check", checkHandler)
	mux.HandleFunc("/health", healthHandler)
	mux.HandleFunc("/hash/compute", hashComputeHandler)
	mux.HandleFunc("/hash/list", hashListHandler)
	mux.HandleFunc("/hash/add", hashAddHandler)
	mux.HandleFunc("/hash/delete", hashDeleteHandler)

	server := &http.Server{
		Addr:    ":" + port,
		Handler: mux,
	}

	fmt.Printf("Server starting on port %s...\n", port)
	fmt.Printf("\n[File Permission & Tamper Check API]\n")
	fmt.Printf("  GET/POST /check              - Check file permissions & hash verification\n")
	fmt.Printf("  GET/POST /hash/compute       - Compute file hash(es)\n")
	fmt.Printf("  GET      /hash/list          - List all standard hashes\n")
	fmt.Printf("  POST     /hash/add           - Add standard hash\n")
	fmt.Printf("  DELETE   /hash/delete        - Delete standard hash\n")
	fmt.Printf("  GET      /health             - Health check\n")
	fmt.Printf("\nSupported hash algorithms: md5, sha1, sha256, sha512 (default: sha256)\n")

	if err := server.ListenAndServe(); err != nil {
		fmt.Fprintf(os.Stderr, "Server error: %v\n", err)
		os.Exit(1)
	}
}
