package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"mime"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/metoro-io/mcp-golang"
	"github.com/metoro-io/mcp-golang/transport/stdio"
)

const (
	// Maximum size for inline content (5MB)
	MAX_INLINE_SIZE = 5 * 1024 * 1024
	// Maximum size for base64 encoding (1MB)
	MAX_BASE64_SIZE = 1 * 1024 * 1024
)

type FileInfo struct {
	Path        string    `json:"path"`
	Size        int64     `json:"size"`
	Created     time.Time `json:"created"`
	Modified    time.Time `json:"modified"`
	Accessed    time.Time `json:"accessed"`
	IsDirectory bool      `json:"isDirectory"`
	IsFile      bool      `json:"isFile"`
	Permissions string    `json:"permissions"`
}

type FilesystemServer struct {
	allowedDirs []string
	server      *mcp_golang.Server
}

func NewFilesystemServer(allowedDirs []string) (*FilesystemServer, error) {
	// Normalize and validate directories
	normalized := make([]string, 0, len(allowedDirs))
	for _, dir := range allowedDirs {
		abs, err := filepath.Abs(dir)
		if err != nil {
			return nil, fmt.Errorf("failed to resolve path %s: %w", dir, err)
		}

		info, err := os.Stat(abs)
		if err != nil {
			return nil, fmt.Errorf(
				"failed to access directory %s: %w",
				abs,
				err,
			)
		}
		if !info.IsDir() {
			return nil, fmt.Errorf("path is not a directory: %s", abs)
		}

		// Ensure the path ends with a separator to prevent prefix matching issues
		// For example, /tmp/foo should not match /tmp/foobar
		normalized = append(normalized, filepath.Clean(abs)+string(filepath.Separator))
	}
	mcpServer := mcp_golang.NewServer(stdio.NewStdioServerTransport(),
		mcp_golang.WithName("secure-filesystem-server"),
		mcp_golang.WithVersion("0.1.0"),
		mcp_golang.WithPaginationLimit(MAX_INLINE_SIZE))
	s := &FilesystemServer{
		allowedDirs: normalized,
		server:      mcpServer,
	}
	err := s.addFeature(context.Background())
	return s, err
}

// isPathInAllowedDirs checks if a path is within any of the allowed directories
func (s *FilesystemServer) isPathInAllowedDirs(path string) bool {
	// Ensure path is absolute and clean
	absPath, err := filepath.Abs(path)
	if err != nil {
		return false
	}
	// Add trailing separator to ensure we're checking a directory or a file within a directory
	// and not a prefix match (e.g., /tmp/foo should not match /tmp/foobar)
	if !strings.HasSuffix(absPath, string(filepath.Separator)) {
		// If it's a file, we need to check its directory
		if info, err := os.Stat(absPath); err == nil && !info.IsDir() {
			absPath = filepath.Dir(absPath) + string(filepath.Separator)
		} else {
			absPath = absPath + string(filepath.Separator)
		}
	}
	// Check if the path is within any of the allowed directories
	for _, dir := range s.allowedDirs {
		if strings.HasPrefix(absPath, dir) {
			return true
		}
	}
	return false
}

func (s *FilesystemServer) validatePath(requestedPath string) (string, error) {
	// Always convert to absolute path first
	abs, err := filepath.Abs(requestedPath)
	if err != nil {
		return "", fmt.Errorf("invalid path: %w", err)
	}

	// Check if path is within allowed directories
	if !s.isPathInAllowedDirs(abs) {
		return "", fmt.Errorf(
			"access denied - path outside allowed directories: %s",
			abs,
		)
	}

	// Handle symlinks
	realPath, err := filepath.EvalSymlinks(abs)
	if err != nil {
		if !os.IsNotExist(err) {
			return "", err
		}
		// For new files, check parent directory
		parent := filepath.Dir(abs)
		realParent, err := filepath.EvalSymlinks(parent)
		if err != nil {
			return "", fmt.Errorf("parent directory does not exist: %s", parent)
		}

		if !s.isPathInAllowedDirs(realParent) {
			return "", fmt.Errorf(
				"access denied - parent directory outside allowed directories",
			)
		}
		return abs, nil
	}

	// Check if the real path (after resolving symlinks) is still within allowed directories
	if !s.isPathInAllowedDirs(realPath) {
		return "", fmt.Errorf(
			"access denied - symlink target outside allowed directories",
		)
	}

	return realPath, nil
}

func (s *FilesystemServer) getFileStats(path string) (FileInfo, error) {
	info, err := os.Stat(path)
	if err != nil {
		return FileInfo{}, err
	}

	return FileInfo{
		Path:        path,
		Size:        info.Size(),
		Created:     info.ModTime(), // Note: ModTime used as birth time isn't always available
		Modified:    info.ModTime(),
		Accessed:    info.ModTime(), // Note: Access time isn't always available
		IsDirectory: info.IsDir(),
		IsFile:      !info.IsDir(),
		Permissions: fmt.Sprintf("%o", info.Mode().Perm()),
	}, nil
}

func (s *FilesystemServer) searchFiles(
	rootPath, pattern string,
) ([]string, error) {
	var results []string
	pattern = strings.ToLower(pattern)

	err := filepath.Walk(
		rootPath,
		func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return nil // Skip errors and continue
			}

			// Try to validate path
			if _, err := s.validatePath(path); err != nil {
				return nil // Skip invalid paths
			}

			if strings.Contains(strings.ToLower(info.Name()), pattern) {
				results = append(results, path)
			}
			isOK, err := filepath.Match(pattern, info.Name())
			if isOK && err == nil {
				results = append(results, path)
			}

			return nil
		},
	)
	if err != nil {
		return nil, err
	}
	return results, nil
}

// detectMimeType tries to determine the MIME type of a file
func detectMimeType(path string) string {
	// First try by extension
	ext := filepath.Ext(path)
	if ext != "" {
		mimeType := mime.TypeByExtension(ext)
		if mimeType != "" {
			return mimeType
		}
	}

	// If that fails, try to read a bit of the file
	file, err := os.Open(path)
	if err != nil {
		return "application/octet-stream" // Default
	}
	defer file.Close()

	// Read first 512 bytes to detect content type
	buffer := make([]byte, 512)
	n, err := file.Read(buffer)
	if err != nil {
		return "application/octet-stream" // Default
	}

	// Use http.DetectContentType
	return http.DetectContentType(buffer[:n])
}

// isTextFile determines if a file is likely a text file based on MIME type
func isTextFile(mimeType string) bool {
	return strings.HasPrefix(mimeType, "text/") ||
		mimeType == "application/json" ||
		mimeType == "application/xml" ||
		mimeType == "application/javascript" ||
		mimeType == "application/x-javascript" ||
		strings.Contains(mimeType, "+xml") ||
		strings.Contains(mimeType, "+json")
}

// isImageFile determines if a file is an image based on MIME type
func isImageFile(mimeType string) bool {
	return strings.HasPrefix(mimeType, "image/")
}

// pathToResourceURI converts a file path to a resource URI
func pathToResourceURI(path string) string {
	return "file://" + path
}

type GetFileInfoArguments struct {
	Path string `json:"path" jsonschema:"required,description=The path to the file or directory"`
}

// handleGetFileInfo handles the "get_file_info" tool call
// and returns a ToolResponse.
// input: {"jsonrpc":"2.0","method":"tools/call","params":{"name":"get_file_info","arguments":{"path":"/Users/your/Downloads/1111.png"}},"id":12}
func (s *FilesystemServer) handleGetFileInfo(ctx context.Context, req GetFileInfoArguments) (*mcp_golang.ToolResponse, error) {
	path := req.Path
	result := &mcp_golang.ToolResponse{}
	if path == "" {
		result.Content = append(result.Content, mcp_golang.NewTextContent(
			fmt.Sprintf("Error path is empty: %v", path),
		))
		return result, errors.New("path is empty")
	}

	// Handle empty or relative paths like "." or "./" by converting to absolute path
	if path == "." || path == "./" {
		// Get current working directory
		cwd, err := os.Getwd()

		if err != nil {
			result.Content = append(result.Content, mcp_golang.NewTextContent(
				fmt.Sprintf("Error resolving current directory: %v", err),
			))
			return result, err
		}
		path = cwd
	}
	validPath, err := s.validatePath(path)
	if err != nil {
		result.Content = append(result.Content, mcp_golang.NewTextContent(
			fmt.Sprintf("Error validate path: %v", err),
		))
		return result, err
	}

	info, err := s.getFileStats(validPath)
	if err != nil {
		result.Content = append(result.Content, mcp_golang.NewTextContent(
			fmt.Sprintf("Error getting file info: %v", err),
		))
		return result, err
	}

	// Get MIME type for files
	mimeType := "directory"
	if info.IsFile {
		mimeType = detectMimeType(validPath)
	}

	resourceURI := pathToResourceURI(validPath)

	// Determine file type text
	var fileTypeText string
	if info.IsDirectory {
		fileTypeText = "Directory"
	} else {
		fileTypeText = "File"
	}
	result.Content = append(result.Content, mcp_golang.NewTextContent(fmt.Sprintf(
		"File information for: %s\n\nSize: %d bytes\nCreated: %s\nModified: %s\nAccessed: %s\nIsDirectory: %v\nIsFile: %v\nPermissions: %s\nMIME Type: %s\nResource URI: %s",
		validPath,
		info.Size,
		info.Created.Format(time.RFC3339),
		info.Modified.Format(time.RFC3339),
		info.Accessed.Format(time.RFC3339),
		info.IsDirectory,
		info.IsFile,
		info.Permissions,
		mimeType,
		resourceURI,
	)),
		mcp_golang.NewTextResourceContent(resourceURI, "text/plain", fmt.Sprintf("%s: %s (%s, %d bytes)",
			fileTypeText,
			validPath,
			mimeType,
			info.Size),
		))
	return result, nil
}

type CreateDirectoryArg struct {
	Path string `json:"path" jsonschema:"required,description=The path to the directory to create"`
}

// handleCreateDirectory handles the "create_directory" tool call
// input: {"jsonrpc":"2.0","method":"tools/call","params":{"name":"create_directory","arguments":{"path":"/Users/your/Downloads/1111"}},"id":12}
func (s *FilesystemServer) handleCreateDirectory(ctx context.Context, request CreateDirectoryArg) (*mcp_golang.ToolResponse, error) {
	result := &mcp_golang.ToolResponse{}
	path := request.Path
	// Handle empty or relative paths like "." or "./" by converting to absolute path
	if path == "." || path == "./" {
		// Get current working directory
		cwd, err := os.Getwd()
		if err != nil {
			result.Content = append(result.Content, mcp_golang.NewTextContent(
				fmt.Sprintf("Error resolving current directory: %v", err),
			))
			return result, err
		}
		path = cwd
	}

	validPath, err := s.validatePath(path)
	if err != nil {
		resourceURI := pathToResourceURI(validPath)
		result.Content = append(result.Content, mcp_golang.NewTextContent(
			fmt.Sprintf("Error: %v", err)))
		result.Content = append(result.Content, mcp_golang.NewTextResourceContent(resourceURI, fmt.Sprintf("Directory: %s", validPath), "text/plain"))
		return result, err
	}

	// Check if path already exists
	if info, err := os.Stat(validPath); err == nil {
		if info.IsDir() {
			// resourceURI := pathToResourceURI(validPath)
			result.Content = append(result.Content, mcp_golang.NewTextContent(
				fmt.Sprintf("Directory already exists: %v", err)))
			return result, err
		}
		result.Content = append(result.Content, mcp_golang.NewTextContent(
			fmt.Sprintf("Error: Path exists but is not a directory: %v", err)))
		return result, err
	}

	if err := os.MkdirAll(validPath, 0755); err != nil {
		result.Content = append(result.Content, mcp_golang.NewTextContent(
			fmt.Sprintf("Error creating directory: %v", err)))
		return result, err
	}
	// Return both text content and embedded resource
	resourceURI := pathToResourceURI(validPath)
	result.Content = append(result.Content, mcp_golang.NewTextContent(fmt.Sprintf("Successfully created directory %s", path)))
	result.Content = append(result.Content, mcp_golang.NewTextResourceContent(resourceURI, fmt.Sprintf("Directory: %s", validPath), "text/plain"))
	return result, err
}

type EmptyArgs struct{}

// handleListAllowedDirectories lists all allowed directories.
// input: {"jsonrpc":"2.0","method":"tools/call","params":{"name":"list_allowed_directories","arguments":{}},"id":12}
func (s *FilesystemServer) handleListAllowedDirectories(request EmptyArgs) (*mcp_golang.ToolResponse, error) {
	// Remove the trailing separator for display purposes
	displayDirs := make([]string, len(s.allowedDirs))
	for i, dir := range s.allowedDirs {
		displayDirs[i] = strings.TrimSuffix(dir, string(filepath.Separator))
	}

	var result strings.Builder
	result.WriteString("Allowed directories:\n\n")

	for _, dir := range displayDirs {
		resourceURI := pathToResourceURI(dir)
		result.WriteString(fmt.Sprintf("%s (%s)\n", dir, resourceURI))
	}

	return &mcp_golang.ToolResponse{
		Content: []*mcp_golang.Content{mcp_golang.NewTextContent(result.String())},
	}, nil
}

type ListDirectoryArg struct {
	Path string `json:"path" jsonschema:"required,description=The path to the directory to list"`
}

// handleListDirectory handles the "list_directory" tool call
// input: {"jsonrpc":"2.0","method":"tools/call","params":{"name":"list_directory","arguments":{"path":"/Users/your/Downloads"}},"id":12}
func (s *FilesystemServer) handleListDirectory(ctx context.Context, request ListDirectoryArg) (*mcp_golang.ToolResponse, error) {
	path := request.Path
	resp := &mcp_golang.ToolResponse{}
	// Handle empty or relative paths like "." or "./" by converting to absolute path
	if path == "." || path == "./" {
		// Get current working directory
		cwd, err := os.Getwd()
		if err != nil {
			resp.Content = append(resp.Content, mcp_golang.NewTextContent(fmt.Sprintf("Error resolving current directory: %v", err)))
			return resp, err
		}
		path = cwd
	}

	validPath, err := s.validatePath(path)
	if err != nil {
		resp.Content = append(resp.Content, mcp_golang.NewTextContent(fmt.Sprintf("Error validatePath : %v", err)))
		return resp, err
	}

	// Check if it's a directory
	info, err := os.Stat(validPath)
	if err != nil {
		resp.Content = append(resp.Content, mcp_golang.NewTextContent(fmt.Sprintf("Error Stat: %v", err)))
		return resp, err
	}

	if !info.IsDir() {
		resp.Content = append(resp.Content, mcp_golang.NewTextContent("Error: Path is not a directory"))
		return resp, err
	}

	entries, err := os.ReadDir(validPath)
	if err != nil {
		resp.Content = append(resp.Content, mcp_golang.NewTextContent(fmt.Sprintf("Error reading directory: %v", err)))
		return resp, err
	}

	var result strings.Builder
	result.WriteString(fmt.Sprintf("Directory listing for: %s\n\n", validPath))

	for _, entry := range entries {
		entryPath := filepath.Join(validPath, entry.Name())
		resourceURI := pathToResourceURI(entryPath)

		if entry.IsDir() {
			result.WriteString(fmt.Sprintf("[DIR]  %s (%s)\n", entry.Name(), resourceURI))
		} else {
			info, err := entry.Info()
			if err == nil {
				result.WriteString(fmt.Sprintf("[FILE] %s (%s) - %d bytes\n",
					entry.Name(), resourceURI, info.Size()))
			} else {
				result.WriteString(fmt.Sprintf("[FILE] %s (%s)\n", entry.Name(), resourceURI))
			}
		}
	}

	// Return both text content and embedded resource
	resourceURI := pathToResourceURI(validPath)
	resp.Content = append(resp.Content, mcp_golang.NewTextContent(result.String()))
	resp.Content = append(resp.Content, mcp_golang.NewTextResourceContent(resourceURI, fmt.Sprintf("Directory: %s", validPath), "text/plain"))
	return resp, err
}

// DirectoryTreeArg represents the arguments for the "tree_directory" tool call.
type DirectoryTreeArg struct {
	Path     string `json:"path" jsonschema:"required,description=The path to the directory to list"`
	Pretty   bool   `json:"pretty" jsonschema:"required，description=Whether to pretty print the directory tree"`
	MaxDepth int    `json:"max_depth" jsonschema:"description=The maximum depth to list,default=3"`
}

// handleTreeDirectory handles the "tree_directory" tool call
// input: {"jsonrpc":"2.0","method":"tools/call","params":{"name":"tree_directory","arguments":{"path":"/Users/your/Downloads","pretty":true,"max_depth":100}},"id":12}
func (s *FilesystemServer) handleTreeDirectory(ctx context.Context, request DirectoryTreeArg) (*mcp_golang.ToolResponse, error) {
	path := request.Path
	pretty := request.Pretty
	maxDepth := request.MaxDepth
	resp := &mcp_golang.ToolResponse{}
	if maxDepth == 0 {
		maxDepth = 100
	} else if maxDepth <= 0 {
		resp.Content = append(resp.Content, mcp_golang.NewTextContent("maxDepth must be a positive integer"))
		return resp, errors.New("maxDepth must be a positive integer")
	}
	validPath, err := s.validatePath(path)
	if err != nil {
		resp.Content = append(resp.Content, mcp_golang.NewTextContent(fmt.Sprintf("Error Stat: %v", err)))
		return resp, err
	}

	type TreeEntry struct {
		Name     string      `json:"name"`
		Type     string      `json:"type"`
		Children []TreeEntry `json:"children,omitempty"`
	}

	var buildTree func(string, int) ([]TreeEntry, error)
	buildTree = func(currentPath string, depth int) ([]TreeEntry, error) {
		entries, err := os.ReadDir(currentPath)
		if err != nil {
			return nil, err
		}
		var result []TreeEntry
		for _, entry := range entries {
			entryData := TreeEntry{
				Name: entry.Name(),
				Type: "file",
			}
			if entry.IsDir() {
				entryData.Type = "directory"
				if depth < maxDepth {
					children, err := buildTree(filepath.Join(currentPath, entry.Name()), depth+1)
					if err != nil {
						return nil, err
					}
					entryData.Children = children
				}
			}
			result = append(result, entryData)
		}
		return result, nil
	}

	tree, err := buildTree(validPath, 0)
	if err != nil {
		resp.Content = append(resp.Content, mcp_golang.NewTextContent(fmt.Sprintf("Error Tree: %v", err)))
		return resp, err
	}
	// If tree is nil, it will serialize to null; we want [] instead.
	if tree == nil {
		tree = []TreeEntry{}
	}
	indent := ""
	if pretty {
		indent = "  "
	}
	jsonData, err := json.MarshalIndent(tree, "", indent)
	if err != nil {
		resp.Content = append(resp.Content, mcp_golang.NewTextContent(fmt.Sprintf("Error Data: %v", err)))
		return resp, err
	}
	resp.Content = append(resp.Content, mcp_golang.NewTextContent(string(jsonData)))
	return resp, nil
}

type MoveFileArg struct {
	Source      string `json:"source" jsonschema:"required,description=The path to the file to move"`
	Destination string `json:"destination" jsonschema:"required,description=The destination path for the file"`
}

// handleMoveFile handles the "move_file" tool call
// input: {"jsonrpc":"2.0","method":"tools/call","params":{"name":"move_file","arguments":{"source":"/Users/your/Downloads/file1.txt","destination":"/Users/your/Documents/file2.txt"}},"id":12}
func (s *FilesystemServer) handleMoveFile(ctx context.Context, request MoveFileArg) (*mcp_golang.ToolResponse, error) {
	source := request.Source
	destination := request.Destination
	result := &mcp_golang.ToolResponse{}
	// Handle empty or relative paths for source
	if source == "." || source == "./" {
		// Get current working directory
		cwd, err := os.Getwd()
		if err != nil {
			result.Content = append(result.Content, mcp_golang.NewTextContent(
				fmt.Sprintf("Error resolving current directory: %v", err),
			))
			return result, err
		}
		source = cwd
	}

	// Handle empty or relative paths for destination
	if destination == "." || destination == "./" {
		// Get current working directory
		cwd, err := os.Getwd()
		if err != nil {
			result.Content = append(result.Content, mcp_golang.NewTextContent(
				fmt.Sprintf("Error resolving current directory: %v", err),
			))
			return result, err
		}
		destination = cwd
	}

	validSource, err := s.validatePath(source)
	if err != nil {
		result.Content = append(result.Content, mcp_golang.NewTextContent(
			fmt.Sprintf("Error with source path: %v", err),
		))
		return result, err
	}

	// Check if source exists
	if _, err := os.Stat(validSource); os.IsNotExist(err) {
		result.Content = append(result.Content, mcp_golang.NewTextContent(
			fmt.Sprintf("Error: Source does not exist: %s", source),
		))
		return result, err
	}

	validDest, err := s.validatePath(destination)
	if err != nil {
		result.Content = append(result.Content, mcp_golang.NewTextContent(
			fmt.Sprintf("Error with destination path: %v", err),
		))
		return result, err
	}

	// Create parent directory for destination if it doesn't exist
	destDir := filepath.Dir(validDest)
	if err := os.MkdirAll(destDir, 0755); err != nil {
		result.Content = append(result.Content, mcp_golang.NewTextContent(
			fmt.Sprintf("Error creating destination directory: %v", err),
		))
		return result, err
	}

	if err := os.Rename(validSource, validDest); err != nil {
		result.Content = append(result.Content, mcp_golang.NewTextContent(
			fmt.Sprintf("Error moving file: %v", err),
		))
		return result, err
	}

	resourceURI := pathToResourceURI(validDest)
	result.Content = append(result.Content, mcp_golang.NewTextContent(fmt.Sprintf(
		"Successfully moved %s to %s",
		source,
		destination,
	)))
	result.Content = append(result.Content, mcp_golang.NewTextResourceContent(resourceURI,
		fmt.Sprintf("Moved file: %s", validDest),
		"text/plain"))
	return result, nil
}

type ReadFileArg struct {
	Path string `json:"path" jsonschema:"required,description=The path to the file to read"`
}

// handleReadFile handles the "read_file" tool call
// input: {"jsonrpc":"2.0","method":"tools/call","params":{"name":"read_file","arguments":{"path":"/Users/your/Documents/file1.txt"}},"id":1}
func (s *FilesystemServer) handleReadFile(ctx context.Context, request ReadFileArg) (*mcp_golang.ToolResponse, error) {
	path := request.Path
	result := &mcp_golang.ToolResponse{}
	// Handle empty or relative paths like "." or "./" by converting to absolute path
	if path == "." || path == "./" {
		// Get current working directory
		cwd, err := os.Getwd()
		if err != nil {
			result.Content = append(result.Content, mcp_golang.NewTextContent(
				fmt.Sprintf("Error resolving current directory: %v", err),
			))
			return result, err
		}
		path = cwd
	}

	validPath, err := s.validatePath(path)
	if err != nil {
		result.Content = append(result.Content, mcp_golang.NewTextContent(
			fmt.Sprintf("Error: %v", err),
		))
		return result, err
	}

	// Check if it's a directory
	info, err := os.Stat(validPath)
	if err != nil {
		result.Content = append(result.Content, mcp_golang.NewTextContent(
			fmt.Sprintf("Error: %v", err),
		))
		return result, err
	}

	if info.IsDir() {
		// For directories, return a resource reference instead
		resourceURI := pathToResourceURI(validPath)
		result.Content = append(result.Content, mcp_golang.NewTextContent(
			fmt.Sprintf("This is a directory. Use the resource URI to browse its contents: %s", resourceURI),
		))
		result.Content = append(result.Content, mcp_golang.NewTextResourceContent(resourceURI,
			fmt.Sprintf("Directory: %s", validPath),
			"text/plain"))
		return result, err
	}

	// Determine MIME type
	mimeType := detectMimeType(validPath)

	// Check file size
	if info.Size() > MAX_INLINE_SIZE {
		// File is too large to inline, return a resource reference
		resourceURI := pathToResourceURI(validPath)
		result.Content = append(result.Content, mcp_golang.NewTextContent(
			fmt.Sprintf("File is too large to display inline (%d bytes). Access it via resource URI: %s", info.Size(), resourceURI),
		))
		result.Content = append(result.Content, mcp_golang.NewTextResourceContent(resourceURI,
			fmt.Sprintf("Large file: %s (%s, %d bytes)", validPath, mimeType, info.Size()),
			"text/plain"))
		return result, err
	}

	// Read file content
	content, err := os.ReadFile(validPath)
	if err != nil {
		result.Content = append(result.Content, mcp_golang.NewTextContent(
			fmt.Sprintf("Error reading file: %v", err),
		))
		return result, err
	}

	// Handle based on content type
	if isTextFile(mimeType) {
		// It's a text file, return as text
		result.Content = append(result.Content, mcp_golang.NewTextContent(
			string(content),
		))
		return result, err
	} else if isImageFile(mimeType) {
		// It's an image file, return as image content
		if info.Size() <= MAX_BASE64_SIZE {
			result.Content = append(result.Content, mcp_golang.NewTextContent(
				fmt.Sprintf("Image file: %s (%s, %d bytes)", validPath, mimeType, info.Size()),
			))
			result.Content = append(result.Content, mcp_golang.NewImageContent(
				base64.StdEncoding.EncodeToString(content),
				mimeType,
			))
			return result, err
		} else {
			// Too large for base64, return a reference
			resourceURI := pathToResourceURI(validPath)
			result.Content = append(result.Content, mcp_golang.NewTextContent(
				fmt.Sprintf("Image file is too large to display inline (%d bytes). Access it via resource URI: %s", info.Size(), resourceURI),
			))
			result.Content = append(result.Content, mcp_golang.NewTextResourceContent(resourceURI,
				fmt.Sprintf("Large image: %s (%s, %d bytes)", validPath, mimeType, info.Size()),
				"text/plain"))
			return result, err
		}
	} else {
		// It's another type of binary file
		resourceURI := pathToResourceURI(validPath)

		if info.Size() <= MAX_BASE64_SIZE {
			// Small enough for base64 encoding
			result.Content = append(result.Content, mcp_golang.NewTextContent(
				fmt.Sprintf("Binary file: %s (%s, %d bytes)", validPath, mimeType, info.Size()),
			))
			result.Content = append(result.Content, mcp_golang.NewBlobResourceContent(resourceURI,
				base64.StdEncoding.EncodeToString(content),
				mimeType))
			return result, err
		} else {
			// Too large for base64, return a reference
			result.Content = append(result.Content, mcp_golang.NewTextContent(
				fmt.Sprintf("Binary file: %s (%s, %d bytes). Access it via resource URI: %s", validPath, mimeType, info.Size(), resourceURI),
			))
			result.Content = append(result.Content, mcp_golang.NewTextResourceContent(resourceURI,
				fmt.Sprintf("Binary file: %s (%s, %d bytes)", validPath, mimeType, info.Size()),
				"text/plain"))
			return result, err
		}
	}
}

type SearchFilesArg struct {
	Path    string `json:"path" jsonschema:"required,description=The path to the directory to search"`
	Pattern string `json:"pattern" jsonschema:"required,description=The search pattern"`
}

// handleSearchFiles handles the "search_files" tool call
// input: {"jsonrpc":"2.0","method":"tools/call","params":{"name":"search_files","arguments":{"path":"/Users/your/Downloads","pattern":"target"}},"id":12}
func (s *FilesystemServer) handleSearchFiles(ctx context.Context, request SearchFilesArg) (*mcp_golang.ToolResponse, error) {
	path := request.Path
	pattern := request.Pattern
	result := &mcp_golang.ToolResponse{}

	// Handle empty or relative paths like "." or "./" by converting to absolute path
	if path == "." || path == "./" {
		// Get current working directory
		cwd, err := os.Getwd()
		if err != nil {
			result.Content = append(result.Content, mcp_golang.NewTextContent(
				fmt.Sprintf("Error resolving current directory: %v", err),
			))
			return result, err
		}
		path = cwd
	}

	validPath, err := s.validatePath(path)
	if err != nil {
		result.Content = append(result.Content, mcp_golang.NewTextContent(
			fmt.Sprintf("Error validating path: %v", err),
		))
		return result, err
	}

	// Perform the file search
	files, err := s.searchFiles(validPath, pattern)
	if err != nil {
		result.Content = append(result.Content, mcp_golang.NewTextContent(
			fmt.Sprintf("Error searching files: %v", err),
		))
		return result, err
	}

	if len(files) == 0 {
		result.Content = append(result.Content, mcp_golang.NewTextContent(
			fmt.Sprintf("No files found matching pattern '%s' in path '%s'", pattern, path),
		))
	} else {
		var fileList strings.Builder
		fileList.WriteString(fmt.Sprintf("Files found matching pattern '%s' in path '%s':\n\n", pattern, path))
		for _, file := range files {
			fileList.WriteString(fmt.Sprintf("- %s\n", file))
		}
		result.Content = append(result.Content, mcp_golang.NewTextContent(fileList.String()))
	}

	return result, nil
}

type WriteFileArg struct {
	Path    string `json:"path" jsonschema:"required,description=The path to the file to write"`
	Content string `json:"content" jsonschema:"required,description=The content to write to the file"`
	Mode    string `json:"mode" jsonschema:"required,description=The write mode (create, append, overwrite)"`
}

// handleWriteFile handles the "write_file" tool call
// input: {"jsonrpc":"2.0","method":"tools/call","params":{"name":"write_file","arguments":{"path":"/Users/your/Documents/file.txt","content":"Hello, World!","mode":"create"}},"id":1}
func (s *FilesystemServer) handleWriteFile(ctx context.Context, request WriteFileArg) (*mcp_golang.ToolResponse, error) {
	path := request.Path
	content := request.Content
	mode := request.Mode
	result := &mcp_golang.ToolResponse{}

	// Handle empty or relative paths like "." or "./" by converting to absolute path
	if path == "." || path == "./" {
		// Get current working directory
		cwd, err := os.Getwd()
		if err != nil {
			result.Content = append(result.Content, mcp_golang.NewTextContent(
				fmt.Sprintf("Error resolving current directory: %v", err),
			))
			return result, err
		}
		path = filepath.Join(cwd, filepath.Base(path))
	}

	validPath, err := s.validatePath(path)
	if err != nil {
		result.Content = append(result.Content, mcp_golang.NewTextContent(
			fmt.Sprintf("Error validating path: %v", err),
		))
		return result, err
	}

	// Determine the write mode
	var file *os.File
	switch mode {
	case "create":
		file, err = os.Create(validPath)
		if err != nil {
			result.Content = append(result.Content, mcp_golang.NewTextContent(
				fmt.Sprintf("Error creating file: %v", err),
			))
			return result, err
		}
	case "append":
		file, err = os.OpenFile(validPath, os.O_APPEND|os.O_WRONLY, 0644)
		if err != nil {
			result.Content = append(result.Content, mcp_golang.NewTextContent(
				fmt.Sprintf("Error opening file for appending: %v", err),
			))
			return result, err
		}
	case "overwrite":
		file, err = os.Create(validPath) // os.Create truncates the file if it already exists
		if err != nil {
			result.Content = append(result.Content, mcp_golang.NewTextContent(
				fmt.Sprintf("Error overwriting file: %v", err),
			))
			return result, err
		}
	default:
		result.Content = append(result.Content, mcp_golang.NewTextContent(
			fmt.Sprintf("Error: unknown write mode '%s'", mode),
		))
		return result, fmt.Errorf("unknown write mode: %s", mode)
	}
	defer file.Close()

	// Write content to the file
	_, err = file.WriteString(content)
	if err != nil {
		result.Content = append(result.Content, mcp_golang.NewTextContent(
			fmt.Sprintf("Error writing to file: %v", err),
		))
		return result, err
	}

	resourceURI := pathToResourceURI(validPath)
	result.Content = append(result.Content, mcp_golang.NewTextContent(fmt.Sprintf(
		"Successfully wrote to file %s",
		path,
	)))
	result.Content = append(result.Content, mcp_golang.NewTextResourceContent(resourceURI,
		fmt.Sprintf("File content: %s", content),
		"text/plain"))
	return result, nil
}

// registerFileResources registers file resources
// list input:{"jsonrpc":"2.0","id":12,"method":"resources/list","params":{}}
// read imput:{"jsonrpc":"2.0","id":12,"method":"resources/read","params":{"uri":"file:///Users/your/Downloads/file.txt"}}
func (s *FilesystemServer) registerFileResources() error {
	for _, dir := range s.allowedDirs {
		err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return err // 遇到错误时终止遍历
			}

			// 只处理文件，跳过目录
			if info.IsDir() {
				return nil
			}

			// 注册文件资源
			resourceURI := pathToResourceURI(path)
			mimeType := detectMimeType(path)
			err = s.server.RegisterResource(resourceURI, info.Name(), fmt.Sprintf("File: %s", info.Name()), mimeType, func() (*mcp_golang.ResourceResponse, error) {
				// 处理文件资源请求，返回文件内容
				content, err := os.ReadFile(path)
				if err != nil {
					return nil, err
				}
				// 根据 MIME 类型决定返回的内容类型
				if isTextFile(mimeType) {
					return mcp_golang.NewResourceResponse(mcp_golang.NewTextEmbeddedResource(resourceURI, string(content), mimeType)), nil
				} else if isImageFile(mimeType) {
					encodedContent := base64.StdEncoding.EncodeToString(content)
					return mcp_golang.NewResourceResponse(mcp_golang.NewBlobEmbeddedResource(resourceURI, encodedContent, mimeType)), nil
				} else {
					// 对于其他二进制文件，可以返回 base64 编码的内容或创建下载链接等
					encodedContent := base64.StdEncoding.EncodeToString(content)
					return mcp_golang.NewResourceResponse(mcp_golang.NewBlobEmbeddedResource(resourceURI, encodedContent, mimeType)), nil
				}
			})
			if err != nil {
				log.Printf("Error registering resource for file %s: %v", path, err)
				return err
			}

			return nil
		})
		if err != nil {
			return fmt.Errorf("error walking directory %s: %v", dir, err)
		}
	}
	return nil
}

func (s *FilesystemServer) addFeature(ctx context.Context) error {
	// {"jsonrpc":"2.0","id":12,"method":"tools/list"}
	err := s.server.RegisterTool("get_file_info",
		"Retrieve detailed metadata about a file or directory.",
		s.handleGetFileInfo)
	err = s.server.RegisterTool("create_directory",
		"PCreate a new directory or ensure a directory exists.",
		s.handleCreateDirectory)
	err = s.server.RegisterTool("list_allowed_directories",
		"Returns the list of directories that this server is allowed to access.",
		s.handleListAllowedDirectories)
	err = s.server.RegisterTool("list_directory",
		"Get a detailed listing of all files and directories in a specified path.",
		s.handleListDirectory)
	err = s.server.RegisterTool("tree_directory",
		"Get a recursive tree view of files and directories as a JSON structure.",
		s.handleTreeDirectory)
	err = s.server.RegisterTool("move_file",
		"Move or rename files and directories.",
		s.handleMoveFile)
	err = s.server.RegisterTool("read_file",
		"Read the complete contents of a file from the file system.",
		s.handleReadFile)
	err = s.server.RegisterTool("search_files",
		"Search for files in a specified path matching a given pattern.",
		s.handleSearchFiles)
	err = s.server.RegisterTool("write_file",
		"Write or modify the content of a file.",
		s.handleWriteFile)

	err = s.registerFileResources()
	if err != nil {
		return err
	}
	return err
}

// Main function to start the server
// start:  ./mcp-filesystem-server /Users/ouerqiang/Downloads
func main() {
	done := make(chan struct{})
	// Parse command line arguments
	if len(os.Args) < 2 {
		fmt.Fprintf(
			os.Stderr,
			"Usage: %s <allowed-directory> [additional-directories...]\n",
			os.Args[0],
		)
		os.Exit(1)
	}

	// Create and start the server
	fs, err := NewFilesystemServer(os.Args[1:])
	if err != nil {
		log.Fatalf("Failed to create server: %v", err)
	}
	err = fs.server.Serve()
	if err != nil {
		panic(err)
	}
	<-done
}
