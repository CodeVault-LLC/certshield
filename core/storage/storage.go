package storage

import (
	"database/sql"
	"fmt"
	"os"
	"strings"

	"github.com/codevault-llc/certshield/types"
	_ "github.com/lib/pq"
)

type Storage interface {
	CreateScan(*types.Scan) error
}

type PostgresStore struct {
	db *sql.DB
}

func NewPostgresStore() (*PostgresStore, error) {
	if os.Getenv("POSTGRES_HOST") == "" {
		return nil, nil
	}

	connStr := fmt.Sprintf(
		"host=%s port=%s user=%s password=%s dbname=%s sslmode=disable",
		os.Getenv("POSTGRES_HOST"),
		os.Getenv("POSTGRES_PORT"),
		os.Getenv("POSTGRES_USER"),
		os.Getenv("POSTGRES_PASSWORD"),
		os.Getenv("POSTGRES_DB"),
	)
	db, err := sql.Open("postgres", connStr)
	if err != nil {
		return nil, err
	}

	if err := db.Ping(); err != nil {
		return nil, err
	}

	return &PostgresStore{
		db: db,
	}, nil
}

func (s *PostgresStore) Init() error {
	if os.Getenv("POSTGRES_HOST") == "" {
		return nil
	}

	if err := s.createScanTable(); err != nil {
		return err
	}

	return nil
}

func (s *PostgresStore) createScanTable() error {
	_, err := s.db.Exec(`
		CREATE TABLE IF NOT EXISTS scans (
			id SERIAL PRIMARY KEY,
			url TEXT NOT NULL,
			domain TEXT NOT NULL,

			score INT NOT NULL,
			entropy FLOAT NOT NULL,
			matches TEXT NOT NULL,

			certificate TEXT NOT NULL,

			issuer_common_name TEXT NOT NULL,
			subject_common_name TEXT NOT NULL,
			issuer_organization TEXT NOT NULL,
			subject_organization TEXT NOT NULL,

			serial_number TEXT NOT NULL,
			not_before TIMESTAMP NOT NULL,
			not_after TIMESTAMP NOT NULL,

			key_usage TEXT NOT NULL,
			extended_key_usage TEXT NOT NULL,
			signature_algorithm TEXT NOT NULL,

			ip_address TEXT NOT NULL,
			country TEXT NOT NULL,
			organization_unit TEXT NOT NULL,

			is_wildcard BOOLEAN NOT NULL,
			is_expired BOOLEAN NOT NULL,
			is_revoked BOOLEAN NOT NULL,

			validation_method TEXT NOT NULL,
			issuance_date TIMESTAMP NOT NULL,

			cert_source TEXT NOT NULL,
			notes TEXT NOT NULL,

			created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
		);
	`)
	if err != nil {
		return err
	}

	return nil
}

func (s *PostgresStore) CreateScan(scan *types.Scan) error {
	if os.Getenv("POSTGRES_HOST") == "" {
		return nil
	}

	matches := strings.Join(scan.Matches, ", ")
	_, err := s.db.Exec(`
		INSERT INTO scans (
			url, domain, score, entropy, matches, certificate,
			issuer_common_name, subject_common_name, issuer_organization, subject_organization,
			serial_number, not_before, not_after, key_usage, extended_key_usage, signature_algorithm,
			ip_address, country, organization_unit, is_wildcard, is_expired, is_revoked,
			validation_method, issuance_date, cert_source, notes
		) VALUES (
			$1, $2, $3, $4, $5, $6,
			$7, $8, $9, $10,
			$11, $12, $13, $14, $15, $16,
			$17, $18, $19, $20, $21, $22,
			$23, $24, $25, $26
		);
	`,
		scan.URL, scan.Domain, scan.Score, scan.Entropy, matches, scan.Certificate,
		scan.IssuerCommonName, scan.SubjectCommonName, scan.IssuerOrganization, scan.SubjectOrganization,
		scan.SerialNumber, scan.NotBefore, scan.NotAfter, scan.KeyUsage, scan.ExtendedKeyUsage, scan.SignatureAlgorithm,
		scan.IPAddress, scan.Country, scan.OrganizationUnit, scan.IsWildcard, scan.IsExpired, scan.IsRevoked,
		scan.ValidationMethod, scan.IssuanceDate, scan.CertSource, scan.Notes,
	)
	if err != nil {
		return err
	}

	return nil
}
