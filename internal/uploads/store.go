package uploads

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/mehmetcagriekici/learn-web-security-golang-starter/internal/database/dbgen"
)

type File struct {
	ID            int64
	UserID        int64
	CustomerName  string
	CustomerEmail string
	OriginalName  string
	StoragePath   string
	ContentType   string
	CreatedAt     string
}

type ImportedDocument struct {
	ID               int64
	ImportedByUserID int64
	ImportedByName   string
	OriginalName     string
	StoragePath      string
	ContentType      string
	CreatedAt        string
}

type Store struct {
	database *sql.DB
	queries  *dbgen.Queries
}

func NewStore(database *sql.DB) *Store {
	return &Store{database: database, queries: dbgen.New(database)}
}

func (store *Store) Create(ctx context.Context, userID int64, originalName string, document StoredDocument) (File, error) {
	fileID, err := store.queries.CreateUploadedFile(ctx, dbgen.CreateUploadedFileParams{
		UserID:       userID,
		OriginalName: originalName,
		StoragePath:  document.StoragePath,
		ContentType:  document.ContentType,
	})
	if err != nil {
		return File{}, fmt.Errorf("create uploaded file: %w", err)
	}
	file, found, err := store.FindByID(ctx, fileID)
	if err != nil {
		return File{}, err
	}
	if !found {
		return File{}, errors.New("created uploaded file was not found")
	}
	return file, nil
}

func (store *Store) FindByID(ctx context.Context, fileID int64) (File, bool, error) {
	row, err := store.queries.GetUploadedFileByID(ctx, fileID)
	if errors.Is(err, sql.ErrNoRows) {
		return File{}, false, nil
	}
	if err != nil {
		return File{}, false, fmt.Errorf("find uploaded file: %w", err)
	}
	return mapFile(row), true, nil
}

func (store *Store) ListForUser(ctx context.Context, userID int64) ([]File, error) {
	rows, err := store.queries.ListUploadedFilesForUser(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("list uploaded files: %w", err)
	}
	files := make([]File, 0, len(rows))
	for _, row := range rows {
		files = append(files, File{
			ID: row.ID, UserID: row.UserID, CustomerName: row.CustomerName, CustomerEmail: row.CustomerEmail,
			OriginalName: row.OriginalName, StoragePath: row.StoragePath, ContentType: row.ContentType, CreatedAt: row.CreatedAt,
		})
	}
	return files, nil
}

func (store *Store) ListAll(ctx context.Context) ([]File, error) {
	rows, err := store.queries.ListAllUploadedFiles(ctx)
	if err != nil {
		return nil, fmt.Errorf("list all uploaded files: %w", err)
	}
	files := make([]File, 0, len(rows))
	for _, row := range rows {
		files = append(files, File{
			ID: row.ID, UserID: row.UserID, CustomerName: row.CustomerName, CustomerEmail: row.CustomerEmail,
			OriginalName: row.OriginalName, StoragePath: row.StoragePath, ContentType: row.ContentType, CreatedAt: row.CreatedAt,
		})
	}
	return files, nil
}

func (store *Store) ListImported(ctx context.Context) ([]ImportedDocument, error) {
	rows, err := store.queries.ListImportedTaxDocuments(ctx)
	if err != nil {
		return nil, fmt.Errorf("list imported tax documents: %w", err)
	}
	documents := make([]ImportedDocument, 0, len(rows))
	for _, row := range rows {
		documents = append(documents, ImportedDocument{
			ID: row.ID, ImportedByUserID: row.ImportedByUserID, ImportedByName: row.ImportedByName,
			OriginalName: row.OriginalName, StoragePath: row.StoragePath, ContentType: row.ContentType, CreatedAt: row.CreatedAt,
		})
	}
	return documents, nil
}

func (store *Store) CreateImported(ctx context.Context, userID int64, archive ExtractedTaxDocumentArchive) ([]ImportedDocument, error) {
	transaction, err := store.database.BeginTx(ctx, nil)
	if err != nil {
		return nil, discardImportedArchive(archive, fmt.Errorf("begin imported tax document transaction: %w", err))
	}
	queries := store.queries.WithTx(transaction)
	documents := make([]ImportedDocument, 0, len(archive.Documents))
	for _, document := range archive.Documents {
		documentID, err := queries.CreateImportedTaxDocument(ctx, dbgen.CreateImportedTaxDocumentParams{
			ImportedByUserID: userID, OriginalName: document.OriginalName, StoragePath: document.StoragePath, ContentType: document.ContentType,
		})
		if err != nil {
			return nil, rollbackAndDiscardImportedArchive(transaction, archive, fmt.Errorf("create imported tax document: %w", err))
		}
		row, err := queries.GetImportedTaxDocumentByID(ctx, documentID)
		if err != nil {
			return nil, rollbackAndDiscardImportedArchive(transaction, archive, fmt.Errorf("find imported tax document: %w", err))
		}
		documents = append(documents, mapImportedDocument(row))
	}
	if err := transaction.Commit(); err != nil {
		return nil, discardImportedArchive(archive, fmt.Errorf("commit imported tax document transaction: %w", err))
	}
	return documents, nil
}

func (store *Store) FindImportedByID(ctx context.Context, documentID int64) (ImportedDocument, bool, error) {
	row, err := store.queries.GetImportedTaxDocumentByID(ctx, documentID)
	if errors.Is(err, sql.ErrNoRows) {
		return ImportedDocument{}, false, nil
	}
	if err != nil {
		return ImportedDocument{}, false, fmt.Errorf("find imported tax document: %w", err)
	}
	return mapImportedDocument(row), true, nil
}

func mapFile(row dbgen.GetUploadedFileByIDRow) File {
	return File{
		ID: row.ID, UserID: row.UserID, CustomerName: row.CustomerName, CustomerEmail: row.CustomerEmail,
		OriginalName: row.OriginalName, StoragePath: row.StoragePath, ContentType: row.ContentType, CreatedAt: row.CreatedAt,
	}
}

func mapImportedDocument(row dbgen.GetImportedTaxDocumentByIDRow) ImportedDocument {
	return ImportedDocument{
		ID: row.ID, ImportedByUserID: row.ImportedByUserID, ImportedByName: row.ImportedByName,
		OriginalName: row.OriginalName, StoragePath: row.StoragePath, ContentType: row.ContentType, CreatedAt: row.CreatedAt,
	}
}

func rollbackAndDiscardImportedArchive(transaction *sql.Tx, archive ExtractedTaxDocumentArchive, err error) error {
	if rollbackErr := transaction.Rollback(); rollbackErr != nil {
		err = errors.Join(err, fmt.Errorf("rollback imported tax document transaction: %w", rollbackErr))
	}
	return discardImportedArchive(archive, err)
}

func discardImportedArchive(archive ExtractedTaxDocumentArchive, err error) error {
	if discardErr := DiscardExtractedTaxDocumentArchive(archive); discardErr != nil {
		return errors.Join(err, discardErr)
	}
	return err
}
