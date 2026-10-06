package cart

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/mehmetcagriekici/learn-web-security-golang-starter/internal/database/dbgen"
)

const MaximumQuantity = 99

type Availability string

const (
	Available             Availability = "available"
	Inactive              Availability = "inactive"
	OutOfStock            Availability = "out-of-stock"
	InsufficientInventory Availability = "insufficient-inventory"
)

type Item struct {
	ID             int64
	UserID         int64
	ProductID      int64
	Quantity       int64
	CreatedAt      string
	UpdatedAt      string
	Name           string
	ImagePath      string
	PriceCents     int64
	InventoryCount int64
	IsActive       bool
	LineTotalCents int64
}

type Store struct {
	queries *dbgen.Queries
}

func NewStore(database *sql.DB) *Store {
	return &Store{queries: dbgen.New(database)}
}

func (store *Store) ListItems(ctx context.Context, userID int64) ([]Item, error) {
	rows, err := store.queries.ListCartItems(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("list cart items: %w", err)
	}
	items := make([]Item, 0, len(rows))
	for _, row := range rows {
		items = append(items, Item{
			ID:             row.ID,
			UserID:         row.UserID,
			ProductID:      row.ProductID,
			Quantity:       row.Quantity,
			CreatedAt:      row.CreatedAt,
			UpdatedAt:      row.UpdatedAt,
			Name:           row.Name,
			ImagePath:      row.ImagePath,
			PriceCents:     row.PriceCents,
			InventoryCount: row.InventoryCount,
			IsActive:       row.IsActive == 1,
			LineTotalCents: row.LineTotalCents,
		})
	}
	return items, nil
}

func (store *Store) ActiveProductExists(ctx context.Context, productID int64) (bool, error) {
	exists, err := store.queries.ActiveCartProductExists(ctx, productID)
	if err != nil {
		return false, fmt.Errorf("find active cart product: %w", err)
	}
	return exists == 1, nil
}

func (store *Store) AddItem(ctx context.Context, userID, productID, quantity int64) (bool, error) {
	result, err := store.queries.AddProductToCart(ctx, dbgen.AddProductToCartParams{
		UserID:    userID,
		ProductID: productID,
		Quantity:  quantity,
	})
	if err != nil {
		return false, fmt.Errorf("add cart item: %w", err)
	}
	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("read added cart rows: %w", err)
	}
	return rowsAffected == 1, nil
}

func (store *Store) UpdateItem(ctx context.Context, userID, productID, quantity int64) (bool, error) {
	if quantity == 0 {
		if err := store.queries.RemoveCartItem(ctx, dbgen.RemoveCartItemParams{UserID: userID, ProductID: productID}); err != nil {
			return false, fmt.Errorf("remove cart item: %w", err)
		}
		return true, nil
	}
	result, err := store.queries.UpdateCartItemQuantity(ctx, dbgen.UpdateCartItemQuantityParams{
		UserID:    userID,
		ProductID: productID,
		Quantity:  quantity,
	})
	if err != nil {
		return false, fmt.Errorf("update cart item: %w", err)
	}
	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("read updated cart rows: %w", err)
	}
	return rowsAffected == 1, nil
}

func ItemAvailability(item Item) Availability {
	if !item.IsActive {
		return Inactive
	}
	if item.InventoryCount == 0 {
		return OutOfStock
	}
	if item.Quantity > item.InventoryCount {
		return InsufficientInventory
	}
	return Available
}

func TotalCents(items []Item) int64 {
	var totalCents int64
	for _, item := range items {
		totalCents += item.LineTotalCents
	}
	return totalCents
}
