package database

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/mehmetcagriekici/learn-web-security-golang-starter/internal/auth/passwords"
	"github.com/mehmetcagriekici/learn-web-security-golang-starter/internal/database/dbgen"
)

const (
	demoPassword        = "password123"
	warehouseAPIKeyHash = "08efe1ae20064a3db693bba1a5003a76ad23fe600085f5457099875176a0eede"
)

type seedUserDefinition struct {
	email       string
	displayName string
	role        string
}

var seedUserDefinitions = []seedUserDefinition{
	{email: "mabel@example.com", displayName: "Mabel Pines", role: "customer"},
	{email: "sancho@example.com", displayName: "Sancho Panza", role: "support"},
	{email: "wendy@example.com", displayName: "Wendy Corduroy", role: "admin"},
	{email: "scarrasco@example.com", displayName: "Samson Carrasco", role: "customer"},
	{email: "consumptive@example.com", displayName: "Clavdia Chauchat", role: "customer"},
	{email: "pacifica@example.com", displayName: "Pacifica Northwest", role: "customer"},
	{email: "vico@example.com", displayName: "Ludovico Settembrini", role: "customer"},
	{email: "grenda@example.com", displayName: "Grenda Grendinator", role: "customer"},
	{email: "eastwest@example.com", displayName: "J’Dinkalage Morgoone", role: "support"},
	{email: "theo@example.com", displayName: "Theo Beers", role: "admin"},
}

var seedProducts = []dbgen.InsertSeedProductParams{
	{Name: "Classic Teddy", Description: "A suspiciously trustworthy bear.", ImagePath: "/product-photos/teddy-bear.webp", PriceCents: 2499, CostCents: 900, InventoryCount: 12, IsActive: 1},
	{Name: "SQLi Sloth", Description: "Moves slowly, concatenates strings quickly.", ImagePath: "/product-photos/sqli-sloth.webp", PriceCents: 1999, CostCents: 650, InventoryCount: 8, IsActive: 1},
	{Name: "CORS Fox", Description: "Friendly from every origin. Probably too friendly.", ImagePath: "/product-photos/cors-fox.webp", PriceCents: 2799, CostCents: 1100, InventoryCount: 5, IsActive: 1},
	{Name: "CSRF Ferret", Description: "Small, fast, and always doing things you didn’t ask for.", ImagePath: "/product-photos/csrf-ferret.webp", PriceCents: 3210, CostCents: 1200, InventoryCount: 17, IsActive: 1},
	{Name: "OAuth Otter", Description: "Trusts everyone at the river. Heedless of outboard motors.", ImagePath: "/product-photos/oauth-otter.webp", PriceCents: 3499, CostCents: 1425, InventoryCount: 6, IsActive: 1},
	{Name: "XSS Axolotl", Description: "Glows if rendered too literally.", ImagePath: "/product-photos/xss-axolotl.webp", PriceCents: 4299, CostCents: 1800, InventoryCount: 3, IsActive: 1},
	{Name: "Rate Limit Raccoon", Description: "Five hugs per minute, max!", ImagePath: "/product-photos/rate-limit-raccoon.webp", PriceCents: 1599, CostCents: 500, InventoryCount: 24, IsActive: 1},
	{Name: "Debug Duck", Description: "Retired after a quack overflow.", ImagePath: "/product-photos/placeholder.png", PriceCents: 999, CostCents: 250, InventoryCount: 0, IsActive: 0},
}

var seedOrders = []dbgen.InsertSeedOrderParams{
	{UserID: 1, Status: "shipped", TotalCents: 4498, AdminNotes: "Gift wrap requested. Do not expose in customer API."},
	{UserID: 1, Status: "paid", TotalCents: 2799, AdminNotes: "Payment processor retry succeeded on second attempt."},
	{UserID: 2, Status: "paid", TotalCents: 7497, AdminNotes: "Employee discount applied manually."},
	{UserID: 3, Status: "pending", TotalCents: 4798, AdminNotes: "High-value customer; verify address before shipping."},
	{UserID: 4, Status: "shipped", TotalCents: 5209, AdminNotes: "Customer expressed interest in donkey plushies."},
	{UserID: 4, Status: "paid", TotalCents: 3210, AdminNotes: ""},
	{UserID: 4, Status: "pending", TotalCents: 7197, AdminNotes: "Shipping address updated to Isle of Barataria."},
	{UserID: 5, Status: "shipped", TotalCents: 7798, AdminNotes: "Deliver to sanatorium front desk; do not leave outside."},
	{UserID: 7, Status: "paid", TotalCents: 2499, AdminNotes: "Customer may call to discuss metaphysics."},
	{UserID: 8, Status: "pending", TotalCents: 6597, AdminNotes: "Large plush order; confirm inventory before packing."},
	{UserID: 8, Status: "refunded", TotalCents: 5997, AdminNotes: "Refunded after duplicate checkout. Keep for audit trail."},
	{UserID: 9, Status: "shipped", TotalCents: 5098, AdminNotes: "Support staff personal order; no staff discount requested."},
	{UserID: 9, Status: "paid", TotalCents: 2799, AdminNotes: ""},
}

var seedOrderItems = []dbgen.InsertSeedOrderItemParams{
	{OrderID: 1, ProductID: 1, Quantity: 1, PriceCents: 2499},
	{OrderID: 1, ProductID: 2, Quantity: 1, PriceCents: 1999},
	{OrderID: 2, ProductID: 3, Quantity: 1, PriceCents: 2799},
	{OrderID: 3, ProductID: 1, Quantity: 3, PriceCents: 2499},
	{OrderID: 4, ProductID: 2, Quantity: 1, PriceCents: 1999},
	{OrderID: 4, ProductID: 3, Quantity: 1, PriceCents: 2799},
	{OrderID: 5, ProductID: 2, Quantity: 1, PriceCents: 1999},
	{OrderID: 5, ProductID: 4, Quantity: 1, PriceCents: 3210},
	{OrderID: 6, ProductID: 4, Quantity: 1, PriceCents: 3210},
	{OrderID: 7, ProductID: 3, Quantity: 2, PriceCents: 2799},
	{OrderID: 7, ProductID: 7, Quantity: 1, PriceCents: 1599},
	{OrderID: 8, ProductID: 5, Quantity: 1, PriceCents: 3499},
	{OrderID: 8, ProductID: 6, Quantity: 1, PriceCents: 4299},
	{OrderID: 9, ProductID: 1, Quantity: 1, PriceCents: 2499},
	{OrderID: 10, ProductID: 1, Quantity: 2, PriceCents: 2499},
	{OrderID: 10, ProductID: 7, Quantity: 1, PriceCents: 1599},
	{OrderID: 11, ProductID: 2, Quantity: 3, PriceCents: 1999},
	{OrderID: 12, ProductID: 5, Quantity: 1, PriceCents: 3499},
	{OrderID: 12, ProductID: 7, Quantity: 1, PriceCents: 1599},
	{OrderID: 13, ProductID: 3, Quantity: 1, PriceCents: 2799},
}

var seedReviews = []dbgen.InsertSeedReviewParams{
	{UserID: 1, ProductID: 1, Rating: 5, Body: "Soft, reliable, and only a little judgmental."},
	{UserID: 2, ProductID: 1, Rating: 4, Body: "Great bear. Could use more pockets for snacks."},
	{UserID: 1, ProductID: 2, Rating: 5, Body: "Slow to arrive, but emotionally available."},
	{UserID: 3, ProductID: 3, Rating: 3, Body: "Too friendly; needs stricter boundaries."},
	{UserID: 4, ProductID: 4, Rating: 5, Body: "Small, fast, and excellent company on long roads."},
	{UserID: 4, ProductID: 7, Rating: 2, Body: "The raccoon was fine, but my inn had terrible soup."},
	{UserID: 5, ProductID: 6, Rating: 4, Body: "Bright enough for gloomy rooms, albeit slightly smug."},
	{UserID: 7, ProductID: 5, Rating: 5, Body: "An enthusiastic but insufficiently dialectical critter."},
	{UserID: 8, ProductID: 3, Rating: 1, Body: "What is this, a fox for ants?! I need a bigger one."},
	{UserID: 9, ProductID: 7, Rating: 4, Body: "Cuddle rate limit documentation could be clearer."},
}

func Reset(ctx context.Context, database *sql.DB) error {
	if err := Migrate(ctx, database); err != nil {
		return err
	}

	seedUsers, err := buildSeedUsers()
	if err != nil {
		return err
	}

	transaction, err := database.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin seed transaction: %w", err)
	}
	defer transaction.Rollback()

	queries := dbgen.New(transaction)
	if err := clearSeedTables(ctx, queries); err != nil {
		return err
	}
	if err := insertSeedData(ctx, queries, seedUsers); err != nil {
		return err
	}
	if err := assertForeignKeyIntegrity(ctx, transaction); err != nil {
		return err
	}
	if err := transaction.Commit(); err != nil {
		return fmt.Errorf("commit seed transaction: %w", err)
	}
	return nil
}

func buildSeedUsers() ([]dbgen.InsertSeedUserParams, error) {
	seedUsers := make([]dbgen.InsertSeedUserParams, 0, len(seedUserDefinitions))
	for _, definition := range seedUserDefinitions {
		passwordHash, err := passwords.Hash(demoPassword)
		if err != nil {
			return nil, fmt.Errorf("hash password for %s: %w", definition.email, err)
		}
		seedUsers = append(seedUsers, dbgen.InsertSeedUserParams{
			Email:        definition.email,
			DisplayName:  definition.displayName,
			Role:         definition.role,
			PasswordHash: passwordHash,
		})
	}
	return seedUsers, nil
}

func clearSeedTables(ctx context.Context, queries *dbgen.Queries) error {
	deleteOperations := []func(context.Context) error{
		queries.DeletePasskeyChallenges,
		queries.DeletePasskeyCredentials,
		queries.DeleteMFARecoveryAttempts,
		queries.DeleteTOTPBackupCodes,
		queries.DeleteImportedTaxDocuments,
		queries.DeleteUploadedFiles,
		queries.DeleteAPIKeyUsage,
		queries.DeleteAPIKeys,
		queries.DeletePasswordResetTokens,
		queries.DeleteReviews,
		queries.DeleteOrderItems,
		queries.DeleteOrders,
		queries.DeleteCartItems,
		queries.DeleteProducts,
		queries.DeleteTOTPLoginChallenges,
		queries.DeleteSessions,
		queries.DeleteUsers,
	}
	for _, deleteRows := range deleteOperations {
		if err := deleteRows(ctx); err != nil {
			return fmt.Errorf("clear seed tables: %w", err)
		}
	}
	return nil
}

func insertSeedData(ctx context.Context, queries *dbgen.Queries, seedUsers []dbgen.InsertSeedUserParams) error {
	for _, seedUser := range seedUsers {
		if err := queries.InsertSeedUser(ctx, seedUser); err != nil {
			return fmt.Errorf("insert user %s: %w", seedUser.Email, err)
		}
	}

	totpSecret := "KXDYU6DRQPRQXLPY236SJJXPNGHQJVUF"
	if err := queries.SetUserTOTPSecret(ctx, dbgen.SetUserTOTPSecretParams{TotpSecret: &totpSecret, Email: "wendy@example.com"}); err != nil {
		return fmt.Errorf("set Wendy TOTP secret: %w", err)
	}
	wendyID, err := queries.GetUserIDByEmail(ctx, "wendy@example.com")
	if err != nil {
		return fmt.Errorf("find Wendy: %w", err)
	}

	backupCodeHash := sha256.Sum256([]byte("a6f31c8d94e2b7504d8a1f3c6b9e2075"))
	if err := queries.InsertSeedTOTPBackupCode(ctx, dbgen.InsertSeedTOTPBackupCodeParams{UserID: wendyID, CodeHash: hex.EncodeToString(backupCodeHash[:])}); err != nil {
		return fmt.Errorf("insert Wendy backup code: %w", err)
	}
	transports := `["internal"]`
	if err := queries.InsertSeedPasskeyCredential(ctx, dbgen.InsertSeedPasskeyCredentialParams{
		UserID:       wendyID,
		CredentialID: "5kcO4l1a45q4ekBss8CXgyyIcYiofd0Sm4tIo9oZqZ0",
		PublicKey:    "pQECAyYgASFYIHeKpJoZLcCWKRxpQ2DMzjLYhe738ROMLeU7ABISzdJJIlggbYVvviIKz_zGqOiZOYQ-9HWfjWgWdTlS7iDmrB1hOzE",
		Transports:   &transports,
	}); err != nil {
		return fmt.Errorf("insert Wendy passkey: %w", err)
	}

	for _, product := range seedProducts {
		if err := queries.InsertSeedProduct(ctx, product); err != nil {
			return fmt.Errorf("insert product %s: %w", product.Name, err)
		}
	}
	for _, order := range seedOrders {
		if err := queries.InsertSeedOrder(ctx, order); err != nil {
			return fmt.Errorf("insert order for user %d: %w", order.UserID, err)
		}
	}
	for _, orderItem := range seedOrderItems {
		if err := queries.InsertSeedOrderItem(ctx, orderItem); err != nil {
			return fmt.Errorf("insert order item for order %d: %w", orderItem.OrderID, err)
		}
	}
	for _, review := range seedReviews {
		if err := queries.InsertSeedReview(ctx, review); err != nil {
			return fmt.Errorf("insert review for user %d: %w", review.UserID, err)
		}
	}

	if err := queries.InsertSeedUploadedFile(ctx, dbgen.InsertSeedUploadedFileParams{
		UserID:       1,
		OriginalName: "mystery-shack-tax-exemption.pdf",
		StoragePath:  "data/uploads/mystery-shack-tax-exemption.pdf",
		ContentType:  "application/pdf",
	}); err != nil {
		return fmt.Errorf("insert uploaded file: %w", err)
	}
	if err := queries.InsertSeedAPIKey(ctx, dbgen.InsertSeedAPIKeyParams{
		Name:    "Warehouse Fulfillment Integration",
		KeyHash: warehouseAPIKeyHash,
		Scope:   "orders:read",
	}); err != nil {
		return fmt.Errorf("insert warehouse API key: %w", err)
	}
	return nil
}

func assertForeignKeyIntegrity(ctx context.Context, transaction *sql.Tx) error {
	rows, err := transaction.QueryContext(ctx, "PRAGMA foreign_key_check")
	if err != nil {
		return fmt.Errorf("check seed foreign keys: %w", err)
	}
	defer rows.Close()

	violations := make([]string, 0)
	for rows.Next() {
		var tableName string
		var rowID sql.NullInt64
		var parentTable string
		var foreignKeyID int
		if err := rows.Scan(&tableName, &rowID, &parentTable, &foreignKeyID); err != nil {
			return fmt.Errorf("scan foreign key violation: %w", err)
		}
		rowIdentifier := "unknown"
		if rowID.Valid {
			rowIdentifier = fmt.Sprintf("%d", rowID.Int64)
		}
		violations = append(violations, fmt.Sprintf("%s[rowid=%s] -> %s", tableName, rowIdentifier, parentTable))
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("read foreign key violations: %w", err)
	}
	if len(violations) > 0 {
		return fmt.Errorf("seed data violates foreign key constraints: %s", strings.Join(violations, ", "))
	}
	return nil
}
