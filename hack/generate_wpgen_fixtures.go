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
	if len(os.Args) != 2 {
		log.Fatal("Usage: go run ./hack/generate_wpgen_fixtures.go <fixtures-directory>")
	}
	defer imagescan.CleanupAll()

	files, err := filepath.Glob(filepath.Join(os.Args[1], "*.scan.json"))
	if err != nil {
		log.Fatalf("cannot list the fixtures: %v", err)
	}
	if len(files) == 0 {
		log.Fatalf("no *.scan.json file in %s", os.Args[1])
	}

	for _, file := range files {
		if err := update(context.Background(), file); err != nil {
			log.Fatalf("%s: %v", file, err)
		}
	}
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

	snapshot, err := imagescan.TakeSnapshot(img.Image, old.Image, old.Platform, old.Lookup)
	if err != nil {
		return err
	}

	out, err := os.Create(file)
	if err != nil {
		return err
	}
	if err := snapshot.Write(out); err != nil {
		out.Close()
		return err
	}
	if err := out.Close(); err != nil {
		return err
	}
	log.Printf("wrote %s: %d executables, %d of %d lookup paths are links",
		file, len(snapshot.Executables), len(snapshot.Links), len(snapshot.Lookup))
	return nil
}
