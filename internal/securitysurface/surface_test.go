package securitysurface

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strconv"
	"testing"
)

const modulePath = "github.com/sentrybottale/owntransit"

func TestIncompleteSecurityBoundariesRemainPrivate(t *testing.T) {
	root := repositoryRoot(t)

	assertExportedSurface(t, filepath.Join(root, "internal/enrollmentexchange"), []string{
		"const ExchangeWebSocketSubprotocol",
		"const MaxBoundResponseSize",
		"const MaxCourierRegistrationSize",
		"const MaxEncryptedRequestSize",
		"const MaxExchangeConnections",
		"const MaxExchangeWireMessage",
		"const MaxInvitationSize",
		"const MaxMailboxLifetime",
		"const MaxMailboxSlots",
		"const MaxMailboxStoredBytes",
		"const MaxOperatorReceiptSize",
		"const MaxSessionSize",
		"const OutcomeCancelled",
		"const OutcomeConfirmed",
		"const OutcomeDeferred",
		"const PhaseApplied",
		"const PhaseCancelled",
		"const PhasePendingComparison",
		"const PhaseReady",
		"const PhaseResponseVerified",
		"const PhaseTranscriptConfirmed",
		"const SafetyWordCount",
		"func AllocationCapabilitySHA256",
		"func ApprovedRequestSetSHA256",
		"func BindResponse",
		"func CreateCourierCredentialStore",
		"func CreateOperatorStore",
		"func CreateTargetStore",
		"func IssueInvitation",
		"func LoadOperatorStore",
		"func LoadTargetStore",
		"func NewCourier",
		"func NewExchangeHandler",
		"func NewMailboxStore",
		"func NewOperatorSession",
		"func NewTargetSession",
		"func OpenOperatorStore",
		"func ParseCourierRegistration",
		"func ParseOperatorSession",
		"func ParseTargetSession",
		"func PrepareClientBootstrap",
		"func ReplaceOperatorStore",
		"func ReplaceTargetStore",
		"func RetireTargetStore",
		"func RotateCourierCredentialStore",
		"method Courier.Consume",
		"method Courier.PutRegisteredResponse",
		"method Courier.PutRequest",
		"method Courier.PutResponse",
		"method Courier.ReadRegisteredRequest",
		"method Courier.ReadRequest",
		"method Courier.ReadResponse",
		"method Courier.RegisterFromCredentialStore",
		"method ExchangeHandler.Serve",
		"method MailboxStore.Consume",
		"method MailboxStore.Create",
		"method MailboxStore.PutRequest",
		"method MailboxStore.PutResponse",
		"method MailboxStore.ReadRequest",
		"method MailboxStore.ReadResponse",
		"method OperatorSession.BindResponse",
		"method OperatorSession.ConfirmTargetWords",
		"method OperatorSession.Encode",
		"method OperatorSession.Generation",
		"method OperatorSession.MailboxAction",
		"method OperatorSession.Phase",
		"method OperatorSession.ProvisionerWords",
		"method OperatorSession.Review",
		"method OperatorSession.SignedRequest",
		"method TargetSession.AcceptBoundResponse",
		"method TargetSession.Cancel",
		"method TargetSession.CompleteReadyProbe",
		"method TargetSession.ConfirmProvisionerWords",
		"method TargetSession.Encode",
		"method TargetSession.Generation",
		"method TargetSession.InvitationSHA256",
		"method TargetSession.MailboxAction",
		"method TargetSession.MailboxTombstone",
		"method TargetSession.Phase",
		"method TargetSession.ReconcileAppliedResponse",
		"method TargetSession.RecordApplied",
		"method TargetSession.RequestSHA256",
		"method TargetSession.TargetWords",
		"method TargetSession.VerifiedEnrollmentResponse",
		"type ClientBootstrap",
		"type ConfirmationOutcome",
		"type Courier",
		"type CourierRegistration",
		"type ExchangeHandler",
		"type InvitationOptions",
		"type IssuedInvitation",
		"type MailboxStore",
		"type OperatorMailboxAction",
		"type OperatorReview",
		"type OperatorSession",
		"type SafetyPhrase",
		"type SessionPhase",
		"type TargetMailboxAction",
		"type TargetMailboxTombstone",
		"type TargetSession",
		"var ErrMailboxUnavailable",
	})
	assertExportedSurface(t, filepath.Join(root, "internal/packagetxn"), []string{
		"func OpenLifecycle",
		"method Manager.Apply",
		"method Manager.Close",
		"method Manager.PreflightApply",
		"method Manager.PreflightRecover",
		"method Manager.PreflightRollback",
		"method Manager.Recover",
		"method Manager.Rollback",
		"method Manager.WithCurrentRuntimeIdentity",
		"type ApplyInput",
		"type Manager",
		"type Result",
		"type RollbackInput",
		"type RuntimeIdentity",
		"var ErrACLVerificationUnavailable",
		"var ErrInvalidDecision",
		"var ErrLocked",
		"var ErrReplay",
		"var ErrResidue",
	})

	assertUnexportedStructFields(t, filepath.Join(root, "internal/packagetxn"), "decision", "Manager")
	assertUnexportedStructFields(t, filepath.Join(root, "internal/enrollmentexchange"), "Courier", "CourierRegistration", "ExchangeHandler", "OperatorSession", "TargetSession")
	assertSelectorOnlyInFunction(
		t,
		filepath.Join(root, "internal/packagetxn"),
		modulePath+"/internal/release",
		"VerifyBundleForInstall",
		"verifyDecision",
	)
	assertNoProductionImportOutside(t, root, modulePath+"/internal/enrollmentexchange",
		filepath.Join(root, "internal/enrollmentexchange"), filepath.Join(root, "cmd/owntransit"), filepath.Join(root, "cmd/owntransit-relay"),
		filepath.Join(root, "cmd/owntransit-provision"), filepath.Join(root, "cmd/owntransitctl"), filepath.Join(root, "internal/enrollmentsetup"))
	assertNoProductionImportOutside(t, root, modulePath+"/internal/packagetxn", filepath.Join(root, "internal/packagetxn"), filepath.Join(root, "cmd/owntransitctl"))
	assertClientRuntimeOnlyEnrollmentSurface(t, filepath.Join(root, "cmd/owntransit"))
}

func assertCompositeLiteralOnlyInFunction(t *testing.T, directory, typeName, functionName string) {
	t.Helper()
	found := 0
	for fileName, file := range parseProductionGoFiles(t, directory) {
		for _, declaration := range file.Decls {
			function, ok := declaration.(*ast.FuncDecl)
			if !ok {
				continue
			}
			ast.Inspect(function, func(node ast.Node) bool {
				literal, ok := node.(*ast.CompositeLit)
				if !ok {
					return true
				}
				identifier, ok := literal.Type.(*ast.Ident)
				if !ok || identifier.Name != typeName || len(literal.Elts) == 0 {
					return true
				}
				found++
				if function.Name.Name != functionName {
					t.Errorf("%s constructs nonempty %s outside %s", fileName, typeName, functionName)
				}
				return true
			})
		}
	}
	if found != 1 {
		t.Fatalf("expected one guarded nonempty %s construction, found %d", typeName, found)
	}
}

func repositoryRoot(t *testing.T) string {
	t.Helper()
	workingDirectory, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	root := filepath.Clean(filepath.Join(workingDirectory, "..", ".."))
	if _, err := os.Stat(filepath.Join(root, "go.mod")); err != nil {
		t.Fatalf("locate repository root: %v", err)
	}
	return root
}

func assertExportedSurface(t *testing.T, directory string, expected []string) {
	t.Helper()
	files := parseProductionGoFiles(t, directory)
	actual := make([]string, 0)
	for _, file := range files {
		for _, declaration := range file.Decls {
			switch value := declaration.(type) {
			case *ast.GenDecl:
				kind := value.Tok.String()
				for _, specification := range value.Specs {
					switch item := specification.(type) {
					case *ast.TypeSpec:
						if ast.IsExported(item.Name.Name) {
							actual = append(actual, kind+" "+item.Name.Name)
						}
					case *ast.ValueSpec:
						for _, name := range item.Names {
							if ast.IsExported(name.Name) {
								actual = append(actual, kind+" "+name.Name)
							}
						}
					}
				}
			case *ast.FuncDecl:
				if !ast.IsExported(value.Name.Name) {
					continue
				}
				if value.Recv == nil {
					actual = append(actual, "func "+value.Name.Name)
					continue
				}
				receiver, ok := receiverName(value.Recv.List[0].Type)
				if !ok {
					t.Fatalf("%s has an unsupported exported receiver", value.Name.Name)
				}
				actual = append(actual, "method "+receiver+"."+value.Name.Name)
			}
		}
	}
	sort.Strings(actual)
	sort.Strings(expected)
	if !reflect.DeepEqual(actual, expected) {
		t.Fatalf("exported surface changed in %s\nactual:   %q\nexpected: %q", directory, actual, expected)
	}
}

func assertUnexportedStructFields(t *testing.T, directory string, typeNames ...string) {
	t.Helper()
	wanted := make(map[string]bool, len(typeNames))
	for _, name := range typeNames {
		wanted[name] = false
	}
	for _, file := range parseProductionGoFiles(t, directory) {
		for _, declaration := range file.Decls {
			generic, ok := declaration.(*ast.GenDecl)
			if !ok || generic.Tok != token.TYPE {
				continue
			}
			for _, specification := range generic.Specs {
				typed := specification.(*ast.TypeSpec)
				if _, ok := wanted[typed.Name.Name]; !ok {
					continue
				}
				structure, ok := typed.Type.(*ast.StructType)
				if !ok {
					t.Fatalf("%s is no longer a struct", typed.Name.Name)
				}
				wanted[typed.Name.Name] = true
				for _, field := range structure.Fields.List {
					if len(field.Names) == 0 {
						t.Fatalf("%s contains an embedded field", typed.Name.Name)
					}
					for _, name := range field.Names {
						if ast.IsExported(name.Name) {
							t.Fatalf("%s.%s exposes an incomplete authorization boundary", typed.Name.Name, name.Name)
						}
					}
				}
			}
		}
	}
	for name, found := range wanted {
		if !found {
			t.Fatalf("guarded type %s is absent", name)
		}
	}
}

func assertPrivateDeclarationUnreferenced(t *testing.T, directory, name string) {
	t.Helper()
	declarations := 0
	identifiers := 0
	for _, file := range parseProductionGoFiles(t, directory) {
		ast.Inspect(file, func(node ast.Node) bool {
			switch value := node.(type) {
			case *ast.FuncDecl:
				if value.Name.Name == name {
					declarations++
				}
			case *ast.Ident:
				if value.Name == name {
					identifiers++
				}
			}
			return true
		})
	}
	if declarations != 1 || identifiers != 1 {
		t.Fatalf("%s must remain one private, unreferenced construction helper; declarations=%d identifiers=%d", name, declarations, identifiers)
	}
}

func assertSelectorOnlyInFunction(t *testing.T, directory, importPath, selectorName, functionName string) {
	t.Helper()
	found := 0
	for fileName, file := range parseProductionGoFiles(t, directory) {
		aliases := importAliases(t, fileName, file)
		for _, declaration := range file.Decls {
			function, ok := declaration.(*ast.FuncDecl)
			if !ok {
				continue
			}
			ast.Inspect(function, func(node ast.Node) bool {
				selector, ok := node.(*ast.SelectorExpr)
				if !ok || selector.Sel.Name != selectorName {
					return true
				}
				identifier, ok := selector.X.(*ast.Ident)
				if !ok || aliases[identifier.Name] != importPath {
					return true
				}
				found++
				if function.Name.Name != functionName {
					t.Errorf("%s uses %s.%s outside %s", fileName, identifier.Name, selectorName, functionName)
				}
				return true
			})
		}
	}
	if found != 1 {
		t.Fatalf("expected one guarded %s selector, found %d", selectorName, found)
	}
}

func assertNoProductionImportOutside(t *testing.T, root, importPath string, allowedDirectories ...string) {
	t.Helper()
	allowed := make(map[string]bool, len(allowedDirectories))
	for _, directory := range allowedDirectories {
		allowed[filepath.Clean(directory)] = true
	}
	err := filepath.WalkDir(root, func(pathValue string, entry os.DirEntry, walkError error) error {
		if walkError != nil {
			return walkError
		}
		if entry.IsDir() {
			switch entry.Name() {
			case ".git", ".private", "dist":
				return filepath.SkipDir
			}
			return nil
		}
		if allowed[filepath.Dir(pathValue)] || filepath.Ext(pathValue) != ".go" || hasTestSuffix(entry.Name()) {
			return nil
		}
		file, err := parser.ParseFile(token.NewFileSet(), pathValue, nil, parser.ImportsOnly)
		if err != nil {
			return err
		}
		for _, imported := range file.Imports {
			value, err := strconv.Unquote(imported.Path.Value)
			if err != nil {
				return err
			}
			if value == importPath {
				return &forbiddenImportError{file: pathValue, path: importPath}
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

type forbiddenImportError struct {
	file string
	path string
}

func (value *forbiddenImportError) Error() string {
	return value.file + " imports incomplete security boundary " + value.path
}

func assertClientRuntimeOnlyEnrollmentSurface(t *testing.T, directory string) {
	t.Helper()
	allowed := map[string]map[string]bool{
		modulePath + "/internal/enrollment": {
			"RoleClient": true,
		},
		modulePath + "/internal/enrollmentexchange": {
			"CreateCourierCredentialStore": true,
			"ErrMailboxUnavailable":        true,
			"MaxBoundResponseSize":         true,
			"MaxCourierRegistrationSize":   true,
			"MaxEncryptedRequestSize":      true,
			"MaxInvitationSize":            true,
			"NewCourier":                   true,
			"PhaseApplied":                 true,
			"PhaseCancelled":               true,
			"PhasePendingComparison":       true,
			"PhaseReady":                   true,
			"PhaseResponseVerified":        true,
			"PhaseTranscriptConfirmed":     true,
			"RotateCourierCredentialStore": true,
			"TargetMailboxAction":          true,
			"TargetMailboxTombstone":       true,
		},
		modulePath + "/internal/enrollmenttarget": {
			"OpenRuntimeGeneration":   true,
			"RuntimeGenerationHandle": true,
		},
	}
	for name, file := range parseProductionGoFiles(t, directory) {
		aliases := importAliases(t, name, file)
		ast.Inspect(file, func(node ast.Node) bool {
			selector, ok := node.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			identifier, ok := selector.X.(*ast.Ident)
			if !ok {
				return true
			}
			pathValue, imported := aliases[identifier.Name]
			allowedSelectors, guarded := allowed[pathValue]
			if imported && guarded && !allowedSelectors[selector.Sel.Name] {
				t.Errorf("%s selects incomplete enrollment authority %s.%s", name, identifier.Name, selector.Sel.Name)
			}
			return true
		})
	}
}

func importAliases(t *testing.T, fileName string, file *ast.File) map[string]string {
	t.Helper()
	aliases := make(map[string]string)
	for _, imported := range file.Imports {
		pathValue, err := strconv.Unquote(imported.Path.Value)
		if err != nil {
			t.Fatalf("%s: parse import: %v", fileName, err)
		}
		alias := filepath.Base(pathValue)
		if imported.Name != nil {
			alias = imported.Name.Name
			if alias == "." {
				t.Fatalf("%s uses a non-auditable import for %s", fileName, pathValue)
			}
			if alias == "_" {
				continue
			}
		}
		aliases[alias] = pathValue
	}
	return aliases
}

func parseProductionGoFiles(t *testing.T, directory string) map[string]*ast.File {
	t.Helper()
	entries, err := os.ReadDir(directory)
	if err != nil {
		t.Fatal(err)
	}
	files := make(map[string]*ast.File)
	set := token.NewFileSet()
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || filepath.Ext(name) != ".go" || hasTestSuffix(name) {
			continue
		}
		parsed, err := parser.ParseFile(set, filepath.Join(directory, name), nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", name, err)
		}
		files[name] = parsed
	}
	return files
}

func hasTestSuffix(name string) bool {
	const suffix = "_test.go"
	return len(name) >= len(suffix) && name[len(name)-len(suffix):] == suffix
}

func receiverName(expression ast.Expr) (string, bool) {
	switch value := expression.(type) {
	case *ast.Ident:
		return value.Name, true
	case *ast.StarExpr:
		return receiverName(value.X)
	default:
		return "", false
	}
}
