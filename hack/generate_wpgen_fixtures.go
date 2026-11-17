//go:build ignore

// generate_wpgen_fixtures rescans the images of the wpgen scan fixtures and
// rewrites them.
//
// Each *.scan.json file in the directory stores the inputs of the scan: the
// reference and the platform of its image, and the lookup paths. The program
// scans that image with imagescan.Scan, the function that wpgen uses, and
// writes the result back to the same file.
//
// Usage: go run ./hack/generate_wpgen_fixtures.go <fixtures-directory>
package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"path/filepath"

	"github.com/kubewarden/runtime-enforcer/internal/imagescan"
)

func main() {
	os.Exit(run())
}

// run returns the exit code. It does not call log.Fatal, because os.Exit
// skips the deferred cleanup.
func run() int {
	if len(os.Args) != 2 {
		log.Print("Usage: go run ./hack/generate_wpgen_fixtures.go <fixtures-directory>")
		return 1
	}
	defer imagescan.CleanupAll()

	files, err := filepath.Glob(filepath.Join(os.Args[1], "*.scan.json"))
	if err != nil {
		log.Printf("cannot list the fixtures: %v", err)
		return 1
	}
	if len(files) == 0 {
		log.Printf("no *.scan.json file in %s", os.Args[1])
		return 1
	}

	for _, file := range files {
		if err := update(context.Background(), file); err != nil {
			log.Printf("%s: %v", file, err)
			return 1
		}
	}
	return 0
}

func update(ctx context.Context, file string) error {
	f, err := os.Open(file)
	if err != nil {
		return err
	}
	old, err := imagescan.ReadSnapshot(f)
	f.Close()
	if err != nil {
		return err
	}
	if old.Image == "" || old.Platform == "" {
		return fmt.Errorf("the fixture has no image or no platform")
	}

	log.Printf("scanning %s (%s)", old.Image, old.Platform)
	img, err := imagescan.Load(ctx, old.Image, imagescan.LoadOptions{
		Sources:  []string{"registry"},
		Platform: old.Platform,
	})
	if err != nil {
		return err
	}
	defer img.Cleanup()

	snapshot, err := imagescan.TakeSnapshot(ctx, img.Image, old.Image, old.Platform, old.Lookup)
	if err != nil {
		return err
	}

	if err := writeFile(file, snapshot); err != nil {
		return err
	}
	log.Printf("wrote %s: %d executables, %d of %d lookup paths are links",
		file, len(snapshot.Executables), len(snapshot.Links), len(snapshot.Lookup))
	return nil
}

// writeFile writes the snapshot to a temporary file, and then renames it to
// file. When a step fails, file keeps its old content, with the inputs of the
// scan. The temporary file is in the same directory, because a rename across
// file systems fails.
func writeFile(file string, snapshot *imagescan.Snapshot) error {
	out, err := os.CreateTemp(filepath.Dir(file), filepath.Base(file)+".*.tmp")
	if err != nil {
		return err
	}
	defer os.Remove(out.Name()) // Fails without effect after the rename.

	if err := snapshot.Write(out); err != nil {
		out.Close()
		return err
	}
	if err := out.Chmod(0o644); err != nil {
		out.Close()
		return err
	}
	if err := out.Close(); err != nil {
		return err
	}
	return os.Rename(out.Name(), file)
}
