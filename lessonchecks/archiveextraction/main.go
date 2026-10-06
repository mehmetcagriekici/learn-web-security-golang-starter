package main

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"io/fs"
	"log"
	"os"
	"path/filepath"
	"reflect"

	"github.com/mehmetcagriekici/learn-web-security-golang-starter/internal/uploads"
)

type results struct {
	NormalArchiveExtracted   bool `json:"normalArchiveExtracted"`
	InsideNormalizationWorks bool `json:"insideNormalizationWorks"`
	TraversalRejected        bool `json:"traversalRejected"`
	NoEscapeOrPartialWrites  bool `json:"noEscapeOrPartialWrites"`
	AbsolutePathRejected     bool `json:"absolutePathRejected"`
	BackslashPathRejected    bool `json:"backslashPathRejected"`
	SymlinkRejected          bool `json:"symlinkRejected"`
}

type archiveEntry struct {
	name     string
	contents []byte
	mode     fs.FileMode
}

func main() {
	output, err := checkArchives()
	if err != nil {
		log.Fatal(err)
	}
	if err := json.NewEncoder(os.Stdout).Encode(output); err != nil {
		log.Fatal(err)
	}
}

func checkArchives() (results, error) {
	root, err := os.MkdirTemp("", "bearly-secure-archive-check-")
	if err != nil {
		return results{}, err
	}
	defer os.RemoveAll(root)

	normalRoot := filepath.Join(root, "normal")
	normalArchive, err := createArchive([]archiveEntry{
		{name: "tax/document.pdf", contents: []byte("tax")},
		{name: "nested/../notes.txt", contents: []byte("notes")},
	})
	if err != nil {
		return results{}, err
	}
	normal, normalErr := extractArchive(normalArchive, normalRoot)
	normalContents, normalReadErr := os.ReadFile(filepath.Join(normal.ImportDirectory, "tax", "document.pdf"))
	notesContents, notesReadErr := os.ReadFile(filepath.Join(normal.ImportDirectory, "notes.txt"))

	traversalRoot := filepath.Join(root, "traversal")
	traversalArchive, err := createArchive([]archiveEntry{
		{name: "safe.txt", contents: []byte("partial")},
		{name: "../escaped.txt", contents: []byte("escaped")},
	})
	if err != nil {
		return results{}, err
	}
	_, traversalErr := extractArchive(traversalArchive, traversalRoot)
	traversalEntries, traversalReadErr := os.ReadDir(traversalRoot)
	if os.IsNotExist(traversalReadErr) {
		traversalEntries = nil
		traversalReadErr = nil
	}

	absoluteRejected, err := rejectsArchive(filepath.Join(root, "absolute"), []archiveEntry{{name: "/absolute.txt", contents: []byte("absolute")}})
	if err != nil {
		return results{}, err
	}
	backslashRejected, err := rejectsArchive(filepath.Join(root, "backslash"), []archiveEntry{{name: "..\\escaped.txt", contents: []byte("backslash")}})
	if err != nil {
		return results{}, err
	}
	symlinkRejected, err := rejectsArchive(filepath.Join(root, "symlink"), []archiveEntry{{name: "link", contents: []byte("../target"), mode: os.ModeSymlink | 0o777}})
	if err != nil {
		return results{}, err
	}

	return results{
		NormalArchiveExtracted:   normalErr == nil && normalReadErr == nil && string(normalContents) == "tax",
		InsideNormalizationWorks: normalErr == nil && notesReadErr == nil && string(notesContents) == "notes",
		TraversalRejected:        traversalErr != nil,
		NoEscapeOrPartialWrites:  traversalReadErr == nil && len(traversalEntries) == 0,
		AbsolutePathRejected:     absoluteRejected,
		BackslashPathRejected:    backslashRejected,
		SymlinkRejected:          symlinkRejected,
	}, nil
}

func rejectsArchive(root string, entries []archiveEntry) (bool, error) {
	contents, err := createArchive(entries)
	if err != nil {
		return false, err
	}
	_, extractErr := extractArchive(contents, root)
	writtenEntries, readErr := os.ReadDir(root)
	if os.IsNotExist(readErr) {
		writtenEntries = nil
		readErr = nil
	}
	return extractErr != nil && readErr == nil && len(writtenEntries) == 0, nil
}

func extractArchive(contents []byte, directory string) (uploads.ExtractedTaxDocumentArchive, error) {
	extractor := reflect.ValueOf(uploads.ExtractTaxDocumentArchive)
	arguments := []reflect.Value{reflect.ValueOf(contents), reflect.ValueOf(directory)}
	if extractor.Type().NumIn() == 3 {
		arguments = append([]reflect.Value{reflect.Zero(extractor.Type().In(0))}, arguments...)
	}
	returned := extractor.Call(arguments)
	archive := returned[0].Interface().(uploads.ExtractedTaxDocumentArchive)
	if returned[1].IsNil() {
		return archive, nil
	}
	return archive, returned[1].Interface().(error)
}

func createArchive(entries []archiveEntry) ([]byte, error) {
	var buffer bytes.Buffer
	archiveWriter := zip.NewWriter(&buffer)
	for _, entry := range entries {
		header := &zip.FileHeader{Name: entry.name, Method: zip.Store}
		if entry.mode != 0 {
			header.SetMode(entry.mode)
		}
		writer, err := archiveWriter.CreateHeader(header)
		if err != nil {
			return nil, err
		}
		if _, err := writer.Write(entry.contents); err != nil {
			return nil, err
		}
	}
	if err := archiveWriter.Close(); err != nil {
		return nil, err
	}
	return buffer.Bytes(), nil
}
