// Run from the repository root through make vault or make test-vault.
// The plugin consumes the public C ABI; no crypto source or archives are copied.
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
)

func main() {
	if err := build(); err != nil {
		fmt.Fprintln(os.Stderr, "vault:", err)
		os.Exit(1)
	}
}

func build() error {
	tests := flag.Bool("test", false, "also run backend integration tests with real native cryptography")
	flag.Parse()
	if runtime.GOOS != "linux" {
		return fmt.Errorf("run this build inside Linux with the native toolchain")
	}
	root, err := os.Getwd()
	if err != nil {
		return err
	}
	const platform, library, executable = "linux", "libhybrid-pq-cp-abe.so", "vault-plugin-abe"
	module := filepath.Join(root, "plugins", "vault", "vault-plugin-abe")
	output := filepath.Join(root, "build", "artifacts", platform, "vault")
	if err := os.MkdirAll(output, 0755); err != nil {
		return err
	}
	native := filepath.Join(root, "lib", library)
	inputs, err := filepath.Glob(filepath.Join(root, "include", "hybrid_pq_cp_abe", "*.h"))
	if err != nil {
		return err
	}
	inputs = append(inputs, native)
	hash := sha256.New()
	for _, path := range inputs {
		file, err := os.Open(path)
		if err != nil {
			return fmt.Errorf("%w; run make shared first", err)
		}
		_, copyErr := io.Copy(hash, file)
		file.Close()
		if copyErr != nil {
			return copyErr
		}
	}
	// Go's cache does not track external headers/libraries. A content-derived
	// C flag invalidates CGO only when the native ABI or library actually changes.
	identity := hex.EncodeToString(hash.Sum(nil))
	env := os.Environ()
	env = replaceEnv(env, "CGO_ENABLED", "1")
	env = replaceEnv(env, "CGO_CFLAGS", strings.TrimSpace(os.Getenv("CGO_CFLAGS")+" -DHCPABE_VAULT_NATIVE_"+identity))
	env = replaceEnv(env, "PATH", output+string(os.PathListSeparator)+os.Getenv("PATH"))
	env = replaceEnv(env, "LD_LIBRARY_PATH", output+":"+os.Getenv("LD_LIBRARY_PATH"))
	if err := copyFile(native, filepath.Join(output, library)); err != nil {
		return err
	}
	command := func(args ...string) error {
		cmd := exec.Command("go", args...)
		cmd.Dir, cmd.Env = module, env
		cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
		return cmd.Run()
	}
	if err := command("build", "-trimpath", "-o", filepath.Join(output, executable), "./cmd/vault-plugin-abe"); err != nil {
		return err
	}
	fmt.Println("Vault plugin:", filepath.Join(output, executable))
	fmt.Println("Native ABI fingerprint:", identity)
	if *tests {
		return command("test", "-count=1", "-v", "./...")
	}
	return nil
}

func replaceEnv(env []string, key, value string) []string {
	result := make([]string, 0, len(env)+1)
	for _, entry := range env {
		name, _, _ := strings.Cut(entry, "=")
		if !strings.EqualFold(name, key) {
			result = append(result, entry)
		}
	}
	return append(result, key+"="+value)
}

func copyFile(source, destination string) error {
	input, err := os.Open(source)
	if err != nil {
		return err
	}
	defer input.Close()
	output, err := os.Create(destination)
	if err != nil {
		return err
	}
	_, err = io.Copy(output, input)
	closeErr := output.Close()
	if err != nil {
		return err
	}
	return closeErr
}
