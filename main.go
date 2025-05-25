package main

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"os"

	"golang.org/x/crypto/scrypt"
)

const (
	// You might want to adjust these parameters based on your security needs and performance constraints
	scryptN      = 32768 // CPU/memory cost factor (must be power of 2)
	scryptR      = 8     // Block size factor
	scryptP      = 1     // Parallelization factor
	scryptKeyLen = 32    // Length of the derived key (in bytes)

	saltsFileName = "salts.json"
)

var userSalts = make(map[string]string) // Map user identifier to base64 encoded salt

// HashPassword generates a salt and hashes the password using scrypt.
// It returns the derived key (hash) and the generated salt.
func HashPassword(password string) ([]byte, []byte, error) {
	// Generate a random salt
	salt := make([]byte, 16) // 16 bytes is a recommended size for scrypt salt
	_, err := rand.Read(salt)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate salt: %w", err)
	}

	// Derive the key using scrypt
	derivedKey, err := scrypt.Key([]byte(password), salt, scryptN, scryptR, scryptP, scryptKeyLen)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to derive key: %w", err)
	}

	return derivedKey, salt, nil
}

// CheckPasswordHash checks if a plaintext password matches a scrypt derived key using the stored salt.
func CheckPasswordHash(password string, derivedKey []byte, salt []byte) bool {
	// Derive a new key using the provided password and the stored salt
	newDerivedKey, err := scrypt.Key([]byte(password), salt, scryptN, scryptR, scryptP, scryptKeyLen)
	if err != nil {
		log.Printf("Failed to derive key during check: %v", err)
		return false
	}

	// Compare the newly derived key with the stored derived key
	// Use a constant-time comparison function to prevent timing attacks
	return constantTimeEquals(derivedKey, newDerivedKey)
}

// constantTimeEquals compares two byte slices in constant time.
func constantTimeEquals(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}

	var result byte = 0
	for i := 0; i < len(a); i++ {
		result |= a[i] ^ b[i]
	}

	return result == 0
}

// loadSalts reads user salts from the salts file.
func loadSalts() error {
	data, err := os.ReadFile(saltsFileName)
	if err != nil {
		if os.IsNotExist(err) {
			// File does not exist, return empty map
			userSalts = make(map[string]string)
			return nil
		}
		return fmt.Errorf("failed to read salts file: %w", err)
	}

	err = json.Unmarshal(data, &userSalts)
	if err != nil {
		return fmt.Errorf("failed to unmarshal salts data: %w", err)
	}

	return nil
}

// saveSalts writes user salts to the salts file.
func saveSalts() error {
	data, err := json.MarshalIndent(userSalts, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal salts data: %w", err)
	}

	err = os.WriteFile(saltsFileName, data, 0600) // Use 0600 for owner read/write permissions
	if err != nil {
		return fmt.Errorf("failed to write salts file: %w", err)
	}

	return nil
}

func main() {
	fmt.Println("Hello, World!")

	// Load existing salts
	err := loadSalts()
	if err != nil {
		log.Fatalf("Error loading salts: %v", err)
	}

	// Example user and password
	userID := "test_user"
	password := "mysecretpassword"

	// In a real application, you would handle user registration and login separately.
	// This demonstrates the hashing and salt storage part.

	// Hash the password and get the derived key and salt
	derivedKey, salt, err := HashPassword(password)
	if err != nil {
		log.Fatalf("Error hashing password: %v", err)
	}

	// Store the salt associated with the user (in memory map and save to file)
	userSalts[userID] = base64.StdEncoding.EncodeToString(salt)
	err = saveSalts()
	if err != nil {
		log.Fatalf("Error saving salts: %v", err)
	}

	fmt.Printf("Password hashed and salt stored for user: %s\n", userID)

	// To check a password, retrieve the salt for the user
	storedSaltBase64, ok := userSalts[userID]
	if !ok {
		log.Fatalf("Salt not found for user: %s\n", userID)
	}
	storedSalt, err := base64.StdEncoding.DecodeString(storedSaltBase64)
	if err != nil {
		log.Fatalf("Failed to decode stored salt: %v", err)
	}

	// Use the stored salt and the provided password to check against the derived key
	isMatch := CheckPasswordHash(password, derivedKey, storedSalt)
	fmt.Printf("Password matches for user %s: %t\n", userID, isMatch)

	incorrectPassword := "wrongpassword"
	isMatchIncorrect := CheckPasswordHash(incorrectPassword, derivedKey, storedSalt)
	fmt.Printf("Incorrect password matches for user %s: %t\n", userID, isMatchIncorrect)
} 