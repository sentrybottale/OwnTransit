//go:build darwin || linux

package paircmd

import (
	"bufio"
	"bytes"
	"context"
	"io"
	"strings"
	"testing"
)

func TestCodeInputBoundAndNoEcho(t *testing.T) {
	secret := "test-private-code"
	var diagnostics bytes.Buffer
	input := strings.NewReader(secret + "\n")
	v, err := readLine(context.Background(), input, bufio.NewReader(input), &diagnostics, "Code: ", len(secret))
	if err != nil || string(v) != secret {
		t.Fatal("bounded input rejected")
	}
	if strings.Contains(diagnostics.String(), secret) {
		t.Fatal("secret echoed to diagnostics")
	}
	input = strings.NewReader(strings.Repeat("x", 33) + "\n")
	if _, err := readLine(context.Background(), input, bufio.NewReader(input), &diagnostics, "Code: ", 32); err == nil {
		t.Fatal("oversized code accepted")
	}
}

func TestCodePromptCancellationDoesNotWaitForInput(t *testing.T){
	in,out:=io.Pipe();defer in.Close();defer out.Close()
	ctx,cancel:=context.WithCancel(context.Background());cancel()
	var diagnostics bytes.Buffer
	if _,err:=readLine(ctx,in,bufio.NewReader(in),&diagnostics,"Code: ",32);err!=context.Canceled{t.Fatalf("cancel = %v",err)}
}
