package admin

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/mehmetcagriekici/learn-web-security-golang-starter/internal/database/dbgen"
)

type Product struct {
	ID             int64
	Name           string
	Description    string
	ImagePath      string
	PriceCents     int64
	CostCents      int64
	InventoryCount int64
	IsActive       bool
	CreatedAt      string
}

type ProductInput struct {
	Name           string
	Description    string
	ImagePath      string
	PriceCents     int64
	CostCents      int64
	InventoryCount int64
	IsActive       bool
}

type Store struct {
	queries *dbgen.Queries
}

func NewStore(database *sql.DB) *Store {
	return &Store{queries: dbgen.New(database)}
}

func (store *Store) ListProducts(ctx context.Context) ([]Product, error) {
	rows, err := store.queries.ListAllProducts(ctx)
	if err != nil {
		return nil, fmt.Errorf("list products: %w", err)
	}
	products := make([]Product, 0, len(rows))
	for _, row := range rows {
		products = append(products, mapProduct(row))
	}
	return products, nil
}

func (store *Store) FindProduct(ctx context.Context, productID int64) (Product, bool, error) {
	row, err := store.queries.GetProductByID(ctx, productID)
	if errors.Is(err, sql.ErrNoRows) {
		return Product{}, false, nil
	}
	if err != nil {
		return Product{}, false, fmt.Errorf("find product: %w", err)
	}
	return mapProduct(row), true, nil
}

func (store *Store) CreateProduct(ctx context.Context, input ProductInput) (Product, error) {
	row, err := store.queries.CreateProduct(ctx, productParams(input))
	if err != nil {
		return Product{}, fmt.Errorf("create product: %w", err)
	}
	return mapProduct(row), nil
}

func (store *Store) UpdateProduct(ctx context.Context, productID int64, input ProductInput) (Product, bool, error) {
	parameters := productParams(input)
	updated, err := store.queries.UpdateProduct(ctx, dbgen.UpdateProductParams{
		Name: parameters.Name, Description: parameters.Description, ImagePath: parameters.ImagePath,
		PriceCents: parameters.PriceCents, CostCents: parameters.CostCents, InventoryCount: parameters.InventoryCount,
		IsActive: parameters.IsActive, ID: productID,
	})
	if errors.Is(err, sql.ErrNoRows) {
		return Product{}, false, nil
	}
	if err != nil {
		return Product{}, false, fmt.Errorf("update product: %w", err)
	}
	return mapProduct(updated), true, nil
}

func productParams(input ProductInput) dbgen.CreateProductParams {
	isActive := int64(0)
	if input.IsActive {
		isActive = 1
	}
	return dbgen.CreateProductParams{
		Name: input.Name, Description: input.Description, ImagePath: input.ImagePath,
		PriceCents: input.PriceCents, CostCents: input.CostCents, InventoryCount: input.InventoryCount, IsActive: isActive,
	}
}

func mapProduct(row dbgen.Product) Product {
	return Product{
		ID: row.ID, Name: row.Name, Description: row.Description, ImagePath: row.ImagePath,
		PriceCents: row.PriceCents, CostCents: row.CostCents, InventoryCount: row.InventoryCount,
		IsActive: row.IsActive == 1, CreatedAt: row.CreatedAt,
	}
}
