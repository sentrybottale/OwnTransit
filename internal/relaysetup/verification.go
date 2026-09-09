package relaysetup

import (
	"context"
	"io"
)

type verificationResultKey struct{}

func ensureVerificationResult(ctx context.Context) context.Context {
	if _, ok := ctx.Value(verificationResultKey{}).(*SetupResult); ok {
		return ctx
	}
	return context.WithValue(ctx, verificationResultKey{}, &SetupResult{})
}
func currentVerification(ctx context.Context) string {
	if result, ok := ctx.Value(verificationResultKey{}).(*SetupResult); ok {
		return result.Verification
	}
	return ""
}

// ApplySetupWithResult preserves the existing apply API while giving the
// frontend an explicit outcome instead of deriving success from output text.
func ApplySetupWithResult(ctx context.Context, plan SetupPlan, confirmed bool, out io.Writer) (SetupResult, error) {
	result := SetupResult{}
	err := ApplySetup(context.WithValue(ctx, verificationResultKey{}, &result), plan, confirmed, out)
	return result, err
}

func recordVerification(ctx context.Context, level string) {
	if result, ok := ctx.Value(verificationResultKey{}).(*SetupResult); ok {
		result.Verification = level
	}
}
