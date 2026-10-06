package reviews

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/mehmetcagriekici/learn-web-security-golang-starter/internal/database/dbgen"
)

type Review struct {
	ID           int64
	UserID       int64
	ProductID    int64
	ProductName  string
	ReviewerName string
	Rating       int64
	Body         string
	CreatedAt    string
	UpdatedAt    string
}

type Store struct {
	queries *dbgen.Queries
}

func NewStore(database *sql.DB) *Store {
	return &Store{queries: dbgen.New(database)}
}

func (store *Store) ListForUser(ctx context.Context, userID int64) ([]Review, error) {
	rows, err := store.queries.ListReviewsForUser(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("list reviews for user: %w", err)
	}
	reviews := make([]Review, 0, len(rows))
	for _, row := range rows {
		reviews = append(reviews, Review{
			ID:           row.ID,
			UserID:       row.UserID,
			ProductID:    row.ProductID,
			ProductName:  row.ProductName,
			ReviewerName: row.ReviewerName,
			Rating:       row.Rating,
			Body:         row.Body,
			CreatedAt:    row.CreatedAt,
			UpdatedAt:    row.UpdatedAt,
		})
	}
	return reviews, nil
}

func (store *Store) FindByID(ctx context.Context, reviewID int64) (Review, bool, error) {
	row, err := store.queries.GetReviewByID(ctx, reviewID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return Review{}, false, nil
		}
		return Review{}, false, fmt.Errorf("find review: %w", err)
	}
	return Review{
		ID:           row.ID,
		UserID:       row.UserID,
		ProductID:    row.ProductID,
		ProductName:  row.ProductName,
		ReviewerName: row.ReviewerName,
		Rating:       row.Rating,
		Body:         row.Body,
		CreatedAt:    row.CreatedAt,
		UpdatedAt:    row.UpdatedAt,
	}, true, nil
}

func (store *Store) ActiveProductExists(ctx context.Context, productID int64) (bool, error) {
	exists, err := store.queries.ActiveReviewProductExists(ctx, productID)
	if err != nil {
		return false, fmt.Errorf("find active review product: %w", err)
	}
	return exists == 1, nil
}

func (store *Store) Create(ctx context.Context, userID, productID, rating int64, body string) error {
	if err := store.queries.CreateReview(ctx, dbgen.CreateReviewParams{UserID: userID, ProductID: productID, Rating: rating, Body: body}); err != nil {
		return fmt.Errorf("create review: %w", err)
	}
	return nil
}

func (store *Store) Update(ctx context.Context, reviewID, rating int64, body string) error {
	if err := store.queries.UpdateReview(ctx, dbgen.UpdateReviewParams{ID: reviewID, Rating: rating, Body: body}); err != nil {
		return fmt.Errorf("update review: %w", err)
	}
	return nil
}

func (store *Store) Delete(ctx context.Context, reviewID int64) error {
	if err := store.queries.DeleteReview(ctx, reviewID); err != nil {
		return fmt.Errorf("delete review: %w", err)
	}
	return nil
}
