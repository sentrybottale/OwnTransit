package release

import "testing"

func TestValidSPDXPackageReference(t *testing.T) {
	tests := []struct {
		name string
		pkg  SPDXPackage
		want bool
	}{
		{
			name: "standard library",
			pkg: SPDXPackage{Name: "Go standard library", VersionInfo: "go1.26.7", DownloadLocation: "https://go.dev/", LicenseDeclared: "BSD-3-Clause",
				ExternalRefs: []SPDXExternalRef{{ReferenceCategory: "PACKAGE-MANAGER", ReferenceType: "purl", ReferenceLocator: "pkg:golang/std@go1.26.7"}}},
			want: true,
		},
		{
			name: "embedded word list",
			pkg: SPDXPackage{Name: BIP39PackageName, VersionInfo: BIP39PackageVersion, DownloadLocation: BIP39DownloadLocation, LicenseDeclared: "MIT", CopyrightText: BIP39CopyrightText,
				ExternalRefs: []SPDXExternalRef{{ReferenceCategory: "PACKAGE-MANAGER", ReferenceType: "purl", ReferenceLocator: BIP39PackagePURL}}},
			want: true,
		},
		{
			name: "Go module",
			pkg: SPDXPackage{Name: "filippo.io/age", VersionInfo: "v1.3.2", DownloadLocation: "NOASSERTION",
				ExternalRefs: []SPDXExternalRef{{ReferenceCategory: "PACKAGE-MANAGER", ReferenceType: "purl", ReferenceLocator: "pkg:golang/filippo.io%2Fage@v1.3.2"}}},
			want: true,
		},
		{
			name: "module path mismatch",
			pkg: SPDXPackage{Name: "filippo.io/age", VersionInfo: "v1.3.2", DownloadLocation: "NOASSERTION",
				ExternalRefs: []SPDXExternalRef{{ReferenceCategory: "PACKAGE-MANAGER", ReferenceType: "purl", ReferenceLocator: "pkg:golang/example.invalid%2Fage@v1.3.2"}}},
		},
		{
			name: "word list metadata mismatch",
			pkg: SPDXPackage{Name: BIP39PackageName, VersionInfo: BIP39PackageVersion, DownloadLocation: BIP39DownloadLocation, LicenseDeclared: "NOASSERTION", CopyrightText: BIP39CopyrightText,
				ExternalRefs: []SPDXExternalRef{{ReferenceCategory: "PACKAGE-MANAGER", ReferenceType: "purl", ReferenceLocator: BIP39PackagePURL}}},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := validSPDXPackageReference(test.pkg); got != test.want {
				t.Fatalf("validSPDXPackageReference() = %v, want %v", got, test.want)
			}
		})
	}
}
