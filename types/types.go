package types

import "time"

type Flags struct {
	Score int

	Matches []string
}

type LogMessage struct {
	Timestamp          time.Time `json:"@timestamp"`           // Time the log was generated
	Domain             string    `json:"domain"`               // Domain associated with the certificate
	Vendor             string    `json:"vendor"`               // Vendor of the certificate or identified source

	Score              int       `json:"score"`                // Risk score associated with the certificate
	Matches            []string  `json:"matches"`              // List of rules or patterns that matched

	Certificate        string    `json:"certificate"`          // Raw certificate data

	IssuerCommonName   string    `json:"issuer_common_name"`   // Common Name of the Issuer
	SubjectCommonName  string    `json:"subject_common_name"`  // Common Name of the Subject
	IssuerOrganization string    `json:"issuer_organization"`  // Organization of the Issuer
	SubjectOrganization string   `json:"subject_organization"` // Organization of the Subject

	SerialNumber       string    `json:"serial_number"`        // Serial number of the certificate
	NotBefore          time.Time `json:"not_before"`           // Start date of the certificate's validity
	NotAfter           time.Time `json:"not_after"`            // Expiry date of the certificate's validity

	KeyUsage           string  `json:"key_usage"`            // Intended key usages of the certificate
	ExtendedKeyUsage   string  `json:"extended_key_usage"`   // Extended key usages of the certificate
	SignatureAlgorithm string    `json:"signature_algorithm"`  // Algorithm used for the certificate's signature

	IPAddress          string    `json:"ip_address"`           // IP address associated with the domain (if available)
	Country            string    `json:"country"`              // Country of the domain or certificate owner
	OrganizationUnit   string    `json:"organization_unit"`    // Organizational unit of the certificate owner

	IsWildcard         bool      `json:"is_wildcard"`          // Indicates if the certificate is a wildcard certificate
	IsExpired          bool      `json:"is_expired"`           // Indicates if the certificate is expired
	IsRevoked          bool      `json:"is_revoked"`           // Indicates if the certificate has been revoked

	ValidationMethod   string    `json:"validation_method"`    // Method used for validation (DV, OV, EV)
	IssuanceDate       time.Time `json:"issuance_date"`        // Date the certificate was issued

	CertSource         string    `json:"cert_source"`          // Source of the certificate (e.g., CT log, abuse.ch)
	Notes              string    `json:"notes"`                // Additional notes or comments
}
