package main

import (
	"archive/tar"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/klauspost/compress/zstd"
	"gopkg.in/yaml.v3"
)

const (
	binRepoURL     = "https://github.com/nexlinux/bin/releases/download"
	portsRepoURL   = "https://github.com/nexlinux/ports.git"
	shiftConfigDir = "/etc/shift"
	shiftVarDir    = "/var/lib/shift"
	shiftDBFile    = "/var/lib/shift/packages.json"
	shiftPortsDir  = "/var/db/nex-ports"
	shiftCacheDir  = "/var/cache/shift"
)

// ─── SourceDef: строка или struct ───
type SourceDef struct {
	URL      string `yaml:"url,omitempty"`
	Checksum string `yaml:"checksum,omitempty"`
	raw      string
}

func (s *SourceDef) UnmarshalYAML(node *yaml.Node) error {
	if node.Kind == yaml.ScalarNode {
		s.raw = node.Value
		return nil
	}
	type plain SourceDef
	return node.Decode((*plain)(s))
}

func (s SourceDef) Script() string {
	if s.raw != "" {
		return s.raw
	}
	if s.URL != "" {
		return fmt.Sprintf("wget -q %q -O source.tar.gz && tar xf source.tar.gz", s.URL)
	}
	return ""
}

type DepInfo struct {
	Build   []string `yaml:"build,omitempty"`
	Runtime []string `yaml:"runtime,omitempty"`
	raw     []string
}

func (d *DepInfo) UnmarshalYAML(node *yaml.Node) error {
	if node.Kind == yaml.SequenceNode {
		return node.Decode(&d.raw)
	}
	type plain DepInfo
	return node.Decode((*plain)(d))
}

func (d DepInfo) RuntimeDeps() []string {
	seen := make(map[string]bool)
	var out []string
	for _, dep := range d.raw {
		if !seen[dep] {
			seen[dep] = true
			out = append(out, dep)
		}
	}
	for _, dep := range d.Runtime {
		if !seen[dep] {
			seen[dep] = true
			out = append(out, dep)
		}
	}
	return out
}

func (d DepInfo) BuildDeps() []string {
	return d.Build
}

func (d DepInfo) AllDeps() []string {
	seen := make(map[string]bool)
	var out []string
	for _, dep := range d.raw {
		if !seen[dep] {
			seen[dep] = true
			out = append(out, dep)
		}
	}
	for _, dep := range d.Runtime {
		if !seen[dep] {
			seen[dep] = true
			out = append(out, dep)
		}
	}
	for _, dep := range d.Build {
		if !seen[dep] {
			seen[dep] = true
			out = append(out, dep)
		}
	}
	return out
}

// ─── Structs ───
type Recipe struct {
	Name     string    `yaml:"name"`
	Version  string    `yaml:"version"`
	Source   SourceDef `yaml:"source"`
	Build    []string  `yaml:"build"`
	Depends  DepInfo   `yaml:"depends,omitempty"`
	Provides []string  `yaml:"provides,omitempty"`
}

type Config struct {
	CFLAGS   string `yaml:"cflags"`
	CXXFLAGS string `yaml:"cxxflags"`
	LDFLAGS  string `yaml:"ldflags"`
	Prefix   string `yaml:"prefix"`
	Mirror   string `yaml:"mirror"`
}

type InstalledPackage struct {
	Name      string   `json:"name"`
	Version   string   `json:"version"`
	Mode      string   `json:"mode"`
	Files     []string `json:"files"`
	Provides  []string `json:"provides,omitempty"`
	Timestamp string   `json:"timestamp"`
}

type PackageDB struct {
	Packages map[string]InstalledPackage `json:"packages"`
}

type BinaryManifest struct {
	Name      string   `json:"name"`
	Version   string   `json:"version"`
	Arch      string   `json:"arch"`
	CFlags    string   `json:"cflags,omitempty"`
	Depends   []string `json:"depends,omitempty"`
	Provides  []string `json:"provides,omitempty"`
	Files     []string `json:"files"`
	Timestamp string   `json:"timestamp"`
}

var (
	config  Config
	db      PackageDB
	verbose = false
)

func init() {
	loadConfig()
	loadDB()
}

func loadConfig() {
	configFile := filepath.Join(shiftConfigDir, "shift.conf")
	data, err := os.ReadFile(configFile)
	if err != nil {
		config = Config{
			CFLAGS:   "-march=native -O2 -pipe",
			CXXFLAGS: "-march=native -O2 -pipe",
			LDFLAGS:  "",
			Prefix:   "/usr/local",
			Mirror:   binRepoURL,
		}
		if verbose {
			log.Printf("[CONFIG] Using defaults (file not found: %v)\n", err)
		}
		return
	}
	if err := yaml.Unmarshal(data, &config); err != nil {
		log.Fatalf("[ERROR] Failed to parse config: %v\n", err)
	}
	if verbose {
		log.Printf("[CONFIG] Loaded from %s\n", configFile)
	}
}

func loadDB() {
	data, err := os.ReadFile(shiftDBFile)
	if err != nil {
		db = PackageDB{Packages: make(map[string]InstalledPackage)}
		if verbose {
			log.Printf("[DB] Starting with empty database\n")
		}
		return
	}
	if err := json.Unmarshal(data, &db); err != nil {
		log.Fatalf("[ERROR] Failed to parse DB: %v\n", err)
	}
	if verbose {
		log.Printf("[DB] Loaded %d packages\n", len(db.Packages))
	}
}

func saveDB() {
	if err := os.MkdirAll(shiftVarDir, 0755); err != nil {
		log.Fatalf("[ERROR] Cannot create var dir: %v\n", err)
	}
	data, err := json.MarshalIndent(db, "", "  ")
	if err != nil {
		log.Fatalf("[ERROR] Cannot marshal DB: %v\n", err)
	}
	if err := os.WriteFile(shiftDBFile, data, 0644); err != nil {
		log.Fatalf("[ERROR] Cannot write DB: %v\n", err)
	}
	if verbose {
		log.Printf("[DB] Saved %d packages\n", len(db.Packages))
	}
}

func checkRoot() {
	if os.Geteuid() != 0 {
		log.Fatalf("[ERROR] shift requires root privileges\n")
	}
}

func main() {
	// Парсим -v
	for i := 0; i < len(os.Args); i++ {
		if os.Args[i] == "-v" {
			verbose = true
			os.Args = append(os.Args[:i], os.Args[i+1:]...)
			i--
		}
	}

	if len(os.Args) < 3 {
		printUsage()
		os.Exit(1)
	}

	mode := os.Args[1]
	action := os.Args[2]
	var pkg, version string

	if len(os.Args) > 3 {
		pkg = os.Args[3]
	}
	if len(os.Args) > 4 {
		version = os.Args[4]
	}

	if mode != "--bin" && mode != "--port" {
		printUsage()
		os.Exit(1)
	}

	modeStr := "bin"
	if mode == "--port" {
		modeStr = "port"
	}

	switch action {
		case "init":
			checkRoot()
			initShift()
		case "sync":
			checkRoot()
			syncPorts()
		case "install":
			if pkg == "" {
				printUsage()
				os.Exit(1)
			}
			checkRoot()
			if modeStr == "bin" {
				installBinary(pkg, version)
			} else {
				installFromPort(pkg)
			}
		case "remove":
			if pkg == "" {
				printUsage()
				os.Exit(1)
			}
			checkRoot()
			removePackage(pkg)
		case "list":
			listPackages()
		case "search":
			if pkg == "" {
				printUsage()
				os.Exit(1)
			}
			searchPackages(pkg)
		case "upgrade":
			checkRoot()
			upgradePackages(modeStr)
		case "build-binary":
			if pkg == "" {
				printUsage()
				os.Exit(1)
			}
			checkRoot()
			buildBinaryPackage(pkg)
		default:
			printUsage()
			os.Exit(1)
	}
}

func printUsage() {
	fmt.Fprintf(os.Stderr, `Usage: shift [--bin | --port] <action> [package] [version]

	Modes:
	--bin   Install precompiled binaries from repository
	--port  Compile and install from source ports

	Actions:
	init          Initialize shift directories and configuration
	sync          Clone/update ports repository
	install       Install a package
	remove        Remove an installed package
	list          List all installed packages
	search        Search installed packages
	upgrade       Upgrade all installed packages
	build-binary  Build a binary package from installed port

	Examples:
	sudo shift init
	sudo shift sync
	sudo shift --bin install curl
	sudo shift --bin install curl 8.0.1
	sudo shift --port install bash
	sudo shift --port build-binary bash
	sudo shift --bin remove curl
	shift --bin list
	shift --bin search curl

	Flags:
	-v        Verbose output

	`)
}

// ─────────────────────────────────────────────────────────────────────────────
//  INIT & SYNC
// ─────────────────────────────────────────────────────────────────────────────

func initShift() {
	fmt.Println("[INIT] Initializing shift package manager...")

	dirs := []string{shiftConfigDir, shiftVarDir, shiftPortsDir, shiftCacheDir}
	for _, dir := range dirs {
		if err := os.MkdirAll(dir, 0755); err != nil {
			log.Fatalf("[ERROR] Cannot create %s: %v\n", dir, err)
		}
		fmt.Printf("  + %s/\n", dir)
	}

	configFile := filepath.Join(shiftConfigDir, "shift.conf")
	if _, err := os.Stat(configFile); err == nil {
		fmt.Printf("  [SKIP] Config already exists\n")
	} else {
		defaultConfig := `cflags: "-march=native -O2 -pipe"
			cxxflags: "-march=native -O2 -pipe"
			ldflags: ""
			prefix: "/usr/local"
			mirror: "https://github.com/nexlinux/bin/releases/download"
			`
			if err := os.WriteFile(configFile, []byte(defaultConfig), 0644); err != nil {
				log.Fatalf("[ERROR] Cannot write config: %v\n", err)
			}
			fmt.Printf("  + Config: %s\n", configFile)
	}

	if _, err := os.Stat(shiftDBFile); err == nil {
		fmt.Printf("  [SKIP] Database already exists\n")
	} else {
		emptyDB := PackageDB{Packages: make(map[string]InstalledPackage)}
		data, _ := json.MarshalIndent(emptyDB, "", "  ")
		os.WriteFile(shiftDBFile, data, 0644)
		fmt.Printf("  + Database: %s\n", shiftDBFile)
	}

	if _, err := os.Stat(filepath.Join(shiftPortsDir, ".git")); err == nil {
		fmt.Println("  [SKIP] Ports already cloned")
	} else {
		fmt.Println("[INIT] Cloning ports repository...")
		cmd := exec.Command("git", "clone", portsRepoURL, shiftPortsDir)
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		if err := cmd.Run(); err != nil {
			fmt.Printf("[WARN] Could not clone ports: %v\n", err)
		} else {
			fmt.Println("  + Ports repository cloned")
		}
	}

	fmt.Println("[INIT] Done! Next: sudo shift sync")
}

func syncPorts() {
	fmt.Println("[SYNC] Synchronizing ports...")
	if _, err := os.Stat(filepath.Join(shiftPortsDir, ".git")); err != nil {
		cmd := exec.Command("git", "clone", portsRepoURL, shiftPortsDir)
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		if err := cmd.Run(); err != nil {
			log.Fatalf("[ERROR] Failed to clone: %v\n", err)
		}
	} else {
		cmd := exec.Command("git", "-C", shiftPortsDir, "pull", "--ff-only")
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		if err := cmd.Run(); err != nil {
			log.Printf("[WARN] Pull failed: %v\n", err)
		}
	}
	fmt.Println("[SYNC] Done")
}

// ─────────────────────────────────────────────────────────────────────────────
//  BINARY INSTALL
// ─────────────────────────────────────────────────────────────────────────────

func installBinary(pkgName, ver string) {
	if existing, exists := db.Packages[pkgName]; exists {
		if ver == "" || existing.Version == ver {
			log.Fatalf("[ERROR] Package %s v%s already installed\n", pkgName, existing.Version)
		}
	}

	releaseVersion := ver
	if releaseVersion == "" {
		releaseVersion = "latest"
	}

	url := fmt.Sprintf("%s/%s/%s.tar.zst", config.Mirror, releaseVersion, pkgName)
	checksumURL := url + ".sha256"

	fmt.Printf("[BIN] Downloading %s (%s)...\n", pkgName, releaseVersion)
	resp, err := http.Get(url)
	if err != nil {
		log.Fatalf("[ERROR] Network error: %v\n", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		log.Fatalf("[ERROR] Package not found (HTTP %s)\n", resp.Status)
	}

	pkgPath := filepath.Join(shiftCacheDir, fmt.Sprintf("%s-%s.tar.zst", pkgName, releaseVersion))
	outFile, err := os.Create(pkgPath)
	if err != nil {
		log.Fatalf("[ERROR] Cache error: %v\n", err)
	}
	if _, err := io.Copy(outFile, resp.Body); err != nil {
		outFile.Close()
		log.Fatalf("[ERROR] Download failed: %v\n", err)
	}
	outFile.Close()

	respChk, errChk := http.Get(checksumURL)
	if errChk == nil && respChk.StatusCode == http.StatusOK {
		chkData, _ := io.ReadAll(respChk.Body)
		respChk.Body.Close()
		fields := strings.Fields(string(chkData))
		if len(fields) > 0 && !verifyChecksum(pkgPath, fields[0]) {
			log.Fatalf("[ERROR] Checksum mismatch\n")
		}
		if verbose {
			fmt.Println("[BIN] Checksum OK")
		}
	}

	// Распаковка во временную директорию
	extractDir := filepath.Join("/tmp", fmt.Sprintf("shift-extract-%d", time.Now().Unix()))
	os.MkdirAll(extractDir, 0755)
	defer os.RemoveAll(extractDir)

	file, err := os.Open(pkgPath)
	if err != nil {
		log.Fatalf("[ERROR] Cannot open cache: %v\n", err)
	}
	defer file.Close()

	zr, err := zstd.NewReader(file)
	if err != nil {
		log.Fatalf("[ERROR] Zstd error: %v\n", err)
	}
	defer zr.Close()

	tr := tar.NewReader(zr)
	var manifest *BinaryManifest
	var filesList []string

	for {
		header, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			log.Fatalf("[ERROR] Tar error: %v\n", err)
		}

		if header.Name == "MANIFEST" {
			data, _ := io.ReadAll(tr)
			var m BinaryManifest
			if err := json.Unmarshal(data, &m); err == nil {
				manifest = &m
			}
			continue
		}

		if header.Typeflag == tar.TypeDir && (header.Name == "." || header.Name == "./") {
			continue
		}

		targetPath := filepath.Join("/", header.Name)
		targetDir := filepath.Dir(targetPath)

		switch header.Typeflag {
			case tar.TypeDir:
				os.MkdirAll(targetPath, os.FileMode(header.Mode))
				filesList = append(filesList, targetPath)
			case tar.TypeReg:
				os.MkdirAll(targetDir, 0755)
				if err := installFileFromTar(tr, targetPath, os.FileMode(header.Mode), &filesList); err != nil {
					log.Printf("[WARN] Cannot install %s: %v\n", targetPath, err)
				}
		}
	}

	// Проверяем зависимости из манифеста
	if manifest != nil {
		for _, dep := range manifest.Depends {
			if _, installed := db.Packages[dep]; !installed {
				fmt.Printf("[WARN] Missing runtime dependency: %s\n", dep)
			}
		}
	}

	db.Packages[pkgName] = InstalledPackage{
		Name:      pkgName,
		Version:   releaseVersion,
		Mode:      "bin",
		Files:     filesList,
		Provides:  manifest.Provides,
		Timestamp: getCurrentTime(),
	}
	saveDB()

	if err := verifyELFDependencies(db.Packages[pkgName]); err != nil {
		fmt.Printf("[WARN] %v\n", err)
	}
	postInstallHook(pkgName, filesList)

	fmt.Printf("[BIN] Installed %s v%s (%d files)\n", pkgName, releaseVersion, len(filesList))
}

func installFileFromTar(tr *tar.Reader, dst string, mode os.FileMode, filesList *[]string) error {
	if isConfigFile(dst) {
		if _, err := os.Stat(dst); err == nil {
			newPath := dst + ".shift-new"
			out, err := os.OpenFile(newPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, mode)
			if err != nil {
				return err
			}
			_, err = io.Copy(out, tr)
			out.Close()
			if err != nil {
				return err
			}
			fmt.Printf("  ! %s (protected, new: %s)\n", dst, newPath)
			*filesList = append(*filesList, newPath)
			return nil
		}
	}
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, mode)
	if err != nil {
		return err
	}
	_, err = io.Copy(out, tr)
	out.Close()
	if err != nil {
		return err
	}
	fmt.Printf("  + %s\n", dst)
	*filesList = append(*filesList, dst)
	return nil
}

// ─────────────────────────────────────────────────────────────────────────────
//  SOURCE INSTALL (PORT)
// ─────────────────────────────────────────────────────────────────────────────

func installFromPort(pkgName string) {
	if _, exists := db.Packages[pkgName]; exists {
		log.Fatalf("[ERROR] Package %s already installed\n", pkgName)
	}

	recipe, err := loadRecipe(pkgName)
	if err != nil {
		log.Fatalf("[ERROR] Cannot read recipe for %s: %v\n", pkgName, err)
	}

	fmt.Printf("[PORT] Building %s v%s...\n", recipe.Name, recipe.Version)

	allDeps := recipe.Depends.AllDeps()
	if len(allDeps) > 0 {
		fmt.Println("[PORT] Resolving dependencies...")
		if err := installDependencies(allDeps, "port"); err != nil {
			log.Fatalf("[ERROR] Dependency resolution failed: %v\n", err)
		}
	}

	buildDir := filepath.Join("/tmp", fmt.Sprintf("shift-%s-%d", pkgName, time.Now().Unix()))
	stagingDir := filepath.Join(buildDir, "staging")
	os.MkdirAll(stagingDir, 0755)
	defer os.RemoveAll(buildDir)

	// Fetch
	fmt.Println("[PORT] Fetching sources...")
	script := recipe.Source.Script()
	if script == "" {
		log.Fatalf("[ERROR] No source defined\n")
	}
	cmd := exec.Command("sh", "-c", script)
	cmd.Dir = buildDir
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		log.Fatalf("[ERROR] Source fetch failed: %v\n", err)
	}

	// Определяем рабочую директорию (поддиректория от tar)
	workDir := buildDir
	entries, _ := os.ReadDir(buildDir)
	var subdirs []string
	for _, e := range entries {
		if e.IsDir() && e.Name() != "staging" {
			subdirs = append(subdirs, e.Name())
		}
	}
	if len(subdirs) == 1 {
		workDir = filepath.Join(buildDir, subdirs[0])
	}

	// Build
	for i, cmdStr := range recipe.Build {
		fmt.Printf("[PORT] Step %d/%d\n", i+1, len(recipe.Build))
		cmd := exec.Command("sh", "-c", cmdStr)
		cmd.Dir = workDir
		cmd.Env = append(os.Environ(),
				 "CFLAGS="+config.CFLAGS,
		   "CXXFLAGS="+config.CXXFLAGS,
		   "LDFLAGS="+config.LDFLAGS,
		   "PREFIX="+config.Prefix,
		   "DESTDIR="+stagingDir,
		   "PKG_CONFIG_PATH="+filepath.Join(config.Prefix, "lib/pkgconfig")+":"+filepath.Join(config.Prefix, "share/pkgconfig"),
		)
		if err := runCommand(cmd); err != nil {
			log.Fatalf("[ERROR] Build step %d failed: %v\n", i+1, err)
		}
	}

	// Install from staging
	fmt.Println("[PORT] Installing files...")
	var filesList []string
	err = filepath.Walk(stagingDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		relPath, _ := filepath.Rel(stagingDir, path)
		if relPath == "." {
			return nil
		}
		targetPath := filepath.Join("/", relPath)
		if info.IsDir() {
			os.MkdirAll(targetPath, info.Mode())
			return nil
		}
		os.MkdirAll(filepath.Dir(targetPath), 0755)
		if err := copyFileWithProtection(path, targetPath, info.Mode(), &filesList); err != nil {
			return err
		}
		return nil
	})
	if err != nil {
		log.Fatalf("[ERROR] Install failed: %v\n", err)
	}

	provides := recipe.Provides
	if len(provides) == 0 {
		provides = filesList
	}

	db.Packages[pkgName] = InstalledPackage{
		Name:      pkgName,
		Version:   recipe.Version,
		Mode:      "port",
		Files:     filesList,
		Provides:  provides,
		Timestamp: getCurrentTime(),
	}
	saveDB()
	exec.Command("ldconfig").Run()
	if err := verifyELFDependencies(db.Packages[pkgName]); err != nil {
		fmt.Printf("[WARN] %v\n", err)
	}
	postInstallHook(pkgName, filesList)

	fmt.Printf("[PORT] Installed %s v%s (%d files)\n", recipe.Name, recipe.Version, len(filesList))
}

func copyFileWithProtection(src, dst string, mode os.FileMode, filesList *[]string) error {
	if isConfigFile(dst) {
		if _, err := os.Stat(dst); err == nil {
			newPath := dst + ".shift-new"
			if err := copyFile(src, newPath); err != nil {
				return err
			}
			os.Chmod(newPath, mode)
			fmt.Printf("  ! %s (protected, new: %s)\n", dst, newPath)
			*filesList = append(*filesList, newPath)
			return nil
		}
	}
	if err := copyFile(src, dst); err != nil {
		return err
	}
	os.Chmod(dst, mode)
	fmt.Printf("  + %s\n", dst)
	*filesList = append(*filesList, dst)
	return nil
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer out.Close()
	_, err = io.Copy(out, in)
	return err
}

func isConfigFile(path string) bool {
	return strings.HasPrefix(path, "/etc/") || strings.HasPrefix(path, "/usr/local/etc/")
}

// ─────────────────────────────────────────────────────────────────────────────
//  DEPENDENCY RESOLUTION
// ─────────────────────────────────────────────────────────────────────────────

func installDependencies(deps []string, mode string) error {
	order, err := topoSort(deps)
	if err != nil {
		return err
	}
	for _, dep := range order {
		if _, installed := db.Packages[dep]; installed {
			continue
		}
		fmt.Printf("[DEPS] Installing %s...\n", dep)
		if mode == "bin" {
			installBinary(dep, "")
		} else {
			installFromPort(dep)
		}
	}
	return nil
}

func topoSort(initialDeps []string) ([]string, error) {
	visited := make(map[string]bool)
	recStack := make(map[string]bool)
	var order []string

	var visit func(string) error
	visit = func(pkg string) error {
		if recStack[pkg] {
			return fmt.Errorf("circular dependency detected: %s", pkg)
		}
		if visited[pkg] {
			return nil
		}
		recStack[pkg] = true

		recipe, err := loadRecipe(pkg)
		if err == nil {
			for _, dep := range recipe.Depends.AllDeps() {
				if err := visit(dep); err != nil {
					return err
				}
			}
		}

		recStack[pkg] = false
		visited[pkg] = true
		order = append(order, pkg)
		return nil
	}

	for _, dep := range initialDeps {
		if err := visit(dep); err != nil {
			return nil, err
		}
	}
	return order, nil
}

func loadRecipe(pkgName string) (*Recipe, error) {
	recipePath := filepath.Join(shiftPortsDir, pkgName, "recipe.yaml")
	data, err := os.ReadFile(recipePath)
	if err != nil {
		return nil, err
	}
	var r Recipe
	if err := yaml.Unmarshal(data, &r); err != nil {
		return nil, err
	}
	return &r, nil
}

// ─────────────────────────────────────────────────────────────────────────────
//  REMOVE
// ─────────────────────────────────────────────────────────────────────────────

func removePackage(pkgName string) {
	pkg, exists := db.Packages[pkgName]
	if !exists {
		log.Fatalf("[ERROR] Package %s not installed\n", pkgName)
	}

	dependents := findDependents(pkgName)
	if len(dependents) > 0 {
		log.Fatalf("[ERROR] Package %s is required by: %v\n", pkgName, dependents)
	}

	fmt.Printf("[REMOVE] Uninstalling %s v%s...\n", pkgName, pkg.Version)

	for i := len(pkg.Files) - 1; i >= 0; i-- {
		filePath := pkg.Files[i]
		info, err := os.Stat(filePath)
		if err != nil {
			if verbose {
				log.Printf("[WARN] File not found: %s\n", filePath)
			}
			continue
		}
		if info.IsDir() {
			if !dirOwnedByOther(filePath, pkgName) && isEmptyDir(filePath) {
				os.Remove(filePath)
				fmt.Printf("  - %s/\n", filePath)
			}
			continue
		}
		if err := os.Remove(filePath); err != nil {
			log.Printf("[WARN] Cannot remove %s: %v\n", filePath, err)
		} else {
			fmt.Printf("  - %s\n", filePath)
		}
	}

	delete(db.Packages, pkgName)
	saveDB()
	fmt.Printf("[REMOVE] Removed %s\n", pkgName)
}

func dirOwnedByOther(dirPath, excludePkg string) bool {
	for name, pkg := range db.Packages {
		if name == excludePkg {
			continue
		}
		for _, f := range pkg.Files {
			if strings.HasPrefix(f, dirPath+"/") || f == dirPath {
				return true
			}
		}
	}
	return false
}

func isEmptyDir(path string) bool {
	entries, err := os.ReadDir(path)
	return err == nil && len(entries) == 0
}

func findDependents(pkgName string) []string {
	var dependents []string
	for name := range db.Packages {
		recipe, err := loadRecipe(name)
		if err != nil {
			continue
		}
		for _, dep := range recipe.Depends.AllDeps() {
			if dep == pkgName {
				dependents = append(dependents, name)
				break
			}
		}
	}
	return dependents
}

// ─────────────────────────────────────────────────────────────────────────────
//  LIST & SEARCH
// ─────────────────────────────────────────────────────────────────────────────

func listPackages() {
	if len(db.Packages) == 0 {
		fmt.Println("No packages installed")
		return
	}
	fmt.Println("Installed packages:")
	fmt.Println("---")
	for _, pkg := range db.Packages {
		fmt.Printf("%s v%s [%s] (%s)\n", pkg.Name, pkg.Version, pkg.Mode, pkg.Timestamp)
		if verbose {
			fmt.Printf("  Files: %d\n", len(pkg.Files))
			for _, f := range pkg.Files {
				fmt.Printf("    - %s\n", f)
			}
		}
	}
}

func searchPackages(query string) {
	found := false
	for name, pkg := range db.Packages {
		if strings.Contains(name, query) {
			fmt.Printf("%s v%s [%s]\n", pkg.Name, pkg.Version, pkg.Mode)
			found = true
		}
	}
	if !found {
		fmt.Println("No packages found")
	}
}

// ─────────────────────────────────────────────────────────────────────────────
//  UPGRADE
// ─────────────────────────────────────────────────────────────────────────────

func upgradePackages(mode string) {
	if len(db.Packages) == 0 {
		fmt.Println("No packages installed")
		return
	}

	type upgradeInfo struct {
		name        string
		oldVersion  string
		newVersion  string
	}
	var upgrades []upgradeInfo

	for name, pkg := range db.Packages {
		recipe, err := loadRecipe(name)
		if err != nil {
			continue
		}
		if recipe.Version != pkg.Version {
			upgrades = append(upgrades, upgradeInfo{name, pkg.Version, recipe.Version})
		}
	}

	if len(upgrades) == 0 {
		fmt.Println("All packages are up to date")
		return
	}

	fmt.Println("Packages to upgrade:")
	for _, u := range upgrades {
		fmt.Printf("  %s: %s -> %s\n", u.name, u.oldVersion, u.newVersion)
	}
	fmt.Println()

	for _, u := range upgrades {
		fmt.Printf("[UPGRADE] %s %s -> %s\n", u.name, u.oldVersion, u.newVersion)
		removePackage(u.name)
		if mode == "bin" {
			installBinary(u.name, "")
		} else {
			installFromPort(u.name)
		}
	}
}

// ─────────────────────────────────────────────────────────────────────────────
//  BUILD BINARY PACKAGE
// ─────────────────────────────────────────────────────────────────────────────

func buildBinaryPackage(pkgName string) {
	pkg, exists := db.Packages[pkgName]
	if !exists {
		log.Fatalf("[ERROR] Package %s not installed\n", pkgName)
	}
	if pkg.Mode != "port" {
		log.Fatalf("[ERROR] Package %s was not built from port\n", pkgName)
	}

	recipe, err := loadRecipe(pkgName)
	if err != nil {
		log.Fatalf("[ERROR] Cannot load recipe: %v\n", err)
	}

	fmt.Printf("[BUILD-BIN] Creating binary package for %s v%s...\n", pkgName, pkg.Version)

	binDir := filepath.Join(shiftCacheDir, "binpkgs")
	os.MkdirAll(binDir, 0755)

	arch := "amd64"
	outPath := filepath.Join(binDir, fmt.Sprintf("%s-%s-%s.tar.zst", pkgName, pkg.Version, arch))
	outFile, err := os.Create(outPath)
	if err != nil {
		log.Fatalf("[ERROR] Cannot create archive: %v\n", err)
	}
	defer outFile.Close()

	zw, err := zstd.NewWriter(outFile, zstd.WithEncoderLevel(zstd.SpeedBestCompression))
	if err != nil {
		log.Fatalf("[ERROR] Zstd writer: %v\n", err)
	}
	defer zw.Close()

	tw := tar.NewWriter(zw)
	defer tw.Close()

	// MANIFEST
	manifest := BinaryManifest{
		Name:      pkgName,
		Version:   pkg.Version,
		Arch:      arch,
		CFlags:    config.CFLAGS,
		Depends:   recipe.Depends.RuntimeDeps(),
		Provides:  pkg.Provides,
		Files:     pkg.Files,
		Timestamp: getCurrentTime(),
	}
	manifestData, _ := json.MarshalIndent(manifest, "", "  ")
	hdr := &tar.Header{
		Name:    "MANIFEST",
		Mode:    0644,
		Size:    int64(len(manifestData)),
		ModTime: time.Now(),
	}
	tw.WriteHeader(hdr)
	tw.Write(manifestData)

	for _, f := range pkg.Files {
		info, err := os.Stat(f)
		if err != nil {
			log.Printf("[WARN] Skipping %s: %v\n", f, err)
			continue
		}
		if info.IsDir() {
			continue
		}
		relPath, _ := filepath.Rel("/", f)
		hdr := &tar.Header{
			Name:    relPath,
			Mode:    int64(info.Mode()),
			Size:    info.Size(),
			ModTime: info.ModTime(),
		}
		if err := tw.WriteHeader(hdr); err != nil {
			log.Printf("[WARN] Tar header %s: %v\n", f, err)
			continue
		}
		in, err := os.Open(f)
		if err != nil {
			log.Printf("[WARN] Cannot open %s: %v\n", f, err)
			continue
		}
		io.Copy(tw, in)
		in.Close()
	}

	fmt.Printf("[BUILD-BIN] Created: %s\n", outPath)
	fmt.Printf("  Files: %d\n", len(pkg.Files))
}

// ─────────────────────────────────────────────────────────────────────────────
//  UTILITIES
// ─────────────────────────────────────────────────────────────────────────────

func runCommand(cmd *exec.Cmd) error {
	if verbose {
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
	}
	return cmd.Run()
}

func verifyChecksum(filePath, expectedSum string) bool {
	file, err := os.Open(filePath)
	if err != nil {
		return false
	}
	defer file.Close()
	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return false
	}
	return hex.EncodeToString(hash.Sum(nil)) == expectedSum
}

func getCurrentTime() string {
	return time.Now().Format(time.RFC3339)
}

func verifyELFDependencies(pkg InstalledPackage) error {
	var missing []string
	for _, f := range pkg.Files {
		if !strings.Contains(f, "/bin/") && !strings.Contains(f, "/lib/") && !strings.Contains(f, "/lib64/") {
			continue
		}
		info, err := os.Stat(f)
		if err != nil || info.IsDir() {
			continue
		}
		head := make([]byte, 4)
		fd, err := os.Open(f)
		if err != nil {
			continue
		}
		fd.Read(head)
		fd.Close()
		if string(head) != "\x7fELF" {
			continue
		}

		cmd := exec.Command("ldd", f)
		out, err := cmd.CombinedOutput()
		if err != nil {
			continue
		}
		lines := strings.Split(string(out), "\n")
		for _, line := range lines {
			if strings.Contains(line, "not found") {
				missing = append(missing, fmt.Sprintf("%s: %s", f, strings.TrimSpace(line)))
			}
		}
	}
	if len(missing) > 0 {
		sort.Strings(missing)
		return fmt.Errorf("missing shared libraries:\n  %s", strings.Join(missing, "\n  "))
	}
	return nil
}

// OpenRC hook
func postInstallHook(pkgName string, files []string) {
	var services []string
	for _, f := range files {
		if strings.HasPrefix(f, "/etc/init.d/") && !strings.HasSuffix(f, ".shift-new") {
			svc := filepath.Base(f)
			services = append(services, svc)
		}
	}
	if len(services) > 0 {
		fmt.Println("[INIT] New OpenRC services detected:")
		for _, svc := range services {
			fmt.Printf("    %s\n", svc)
			fmt.Printf("    Run: rc-update add %s default\n", svc)
		}
	}
}
