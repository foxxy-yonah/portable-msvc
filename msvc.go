package main

import (
    "archive/zip"
    "bytes"
    "crypto/sha256"
    "encoding/json"
    "flag"
    "fmt"
    "io"
    "net/http"
    "os"
    "os/exec"
    "path/filepath"
    "regexp"
    "sort"
    "strings"
    "syscall"
)

// Constants
const (
    OUTPUT         = "msvc"      // output folder (will be converted to absolute path)
    DOWNLOADS      = "downloads" // temporary download files
    DEFAULT_HOST   = "x64"
    DEFAULT_TARGET = "x64"
    MANIFEST_URL       = "https://aka.ms/vs/17/release/channel"
    MANIFEST_PREVIEW_URL = "https://aka.ms/vs/17/pre/channel"
)

var (
    ALL_HOSTS   = []string{"x64", "x86", "arm64"}
    ALL_TARGETS = []string{"x64", "x86", "arm", "arm64"}
)

// Command-line flags
type args struct {
    showVersions  bool
    acceptLicense bool
    msvcVersion   string
    sdkVersion    string
    preview       bool
    host          string
    target        string
}

// Utility function to replace slices.Contains for Go <1.21 compatibility
func contains(slice []string, item string) bool {
    for _, s := range slice {
        if s == item {
            return true
        }
    }
    return false
}

func download(url string) ([]byte, error) {
    fmt.Printf("[INFO] Downloading from %s\n", url)
    resp, err := http.Get(url)
    if err != nil {
        return nil, fmt.Errorf("failed to download %s: %w", url, err)
    }
    defer resp.Body.Close()
    data, err := io.ReadAll(resp.Body)
    if err != nil {
        return nil, fmt.Errorf("failed to read response from %s: %w", url, err)
    }
    fmt.Printf("[INFO] Downloaded %d bytes from %s\n", len(data), url)
    return data, nil
}

var totalDownload int64

func downloadProgress(url, check, filename string) ([]byte, error) {
    fpath := filepath.Join(DOWNLOADS, filename)
    fmt.Printf("[INFO] Checking if %s exists\n", fpath)
    if data, err := os.ReadFile(fpath); err == nil {
        hash := fmt.Sprintf("%x", sha256.Sum256(data))
        if strings.ToLower(hash) == strings.ToLower(check) {
            fmt.Printf("[INFO] %s exists and hash matches\n", filename)
            return data, nil
        }
        fmt.Printf("[INFO] %s exists but hash does not match, redownloading\n", filename)
    }

    fmt.Printf("[INFO] Downloading %s to %s\n", url, fpath)
    resp, err := http.Get(url)
    if err != nil {
        return nil, fmt.Errorf("failed to download %s: %w", url, err)
    }
    defer resp.Body.Close()

    total := resp.ContentLength
    var data bytes.Buffer
    f, err := os.Create(fpath)
    if err != nil {
        return nil, fmt.Errorf("failed to create %s: %w", fpath, err)
    }
    defer f.Close()

    var size int64
    buf := make([]byte, 1<<20)
    for {
        n, err := resp.Body.Read(buf)
        if n > 0 {
            if _, err := f.Write(buf[:n]); err != nil {
                return nil, fmt.Errorf("failed to write to %s: %w", fpath, err)
            }
            if _, err := data.Write(buf[:n]); err != nil {
                return nil, fmt.Errorf("failed to write to buffer: %w", err)
            }
            size += int64(n)
            if total > 0 {
                perc := size * 100 / total
                fmt.Printf("\r[INFO] %s ... %d%%", filename, perc)
            }
        }
        if err == io.EOF {
            break
        }
        if err != nil {
            return nil, fmt.Errorf("failed to read response: %w", err)
        }
    }
    fmt.Println()

    result := data.Bytes()
    hash := fmt.Sprintf("%x", sha256.Sum256(result))
    if strings.ToLower(check) != strings.ToLower(hash) {
        return nil, fmt.Errorf("hash mismatch for %s", filename)
    }
    totalDownload += int64(len(result))
    fmt.Printf("[INFO] Downloaded %s, size %d bytes, hash verified\n", filename, len(result))
    return result, nil
}

func getMsiCabs(msi []byte) []string {
    fmt.Printf("[INFO] Extracting .cab references from MSI (size: %d bytes)\n", len(msi))
    var cabs []string
    index := 0
    maxIterations := 10000 // DEBUG: Preventing infinite loops, remove this later on
    for i := 0; i < maxIterations; i++ {
        // Search for .cab starting from current index
        nextIndex := bytes.Index(msi[index:], []byte(".cab"))
        if nextIndex < 0 {
            break
        }
        // Adjust index to point to the end of .cab
        index += nextIndex + 4
        if index-36 < 0 || index > len(msi) {
            fmt.Printf("[INFO] Skipping invalid .cab reference at index %d\n", index)
            continue
        }
        // Extract 36 bytes (32 before .cab + .cab)
        cab := string(msi[index-36 : index])
        // Basic validation: ensure it looks like a filename
        if strings.Contains(cab, "\x00") || len(cab) < 5 {
            fmt.Printf("[INFO] Skipping invalid .cab reference: %s\n", cab)
            continue
        }
        cabs = append(cabs, cab)
        fmt.Printf("[INFO] Found .cab reference: %s (total: %d)\n", cab, len(cabs))
    }
    if len(cabs) >= maxIterations {
        fmt.Printf("[INFO] Reached maximum iterations (%d), stopping .cab extraction\n", maxIterations)
    }
    fmt.Printf("[INFO] Found %d .cab references\n", len(cabs))
    return cabs
}

func first[T any](items []T, cond func(T) bool) (T, bool) {
    for _, item := range items {
        if cond(item) {
            return item, true
        }
    }
    var zero T
    return zero, false
}

type manifestItem struct {
    ID       string `json:"id"`
    Payloads []struct {
        URL      string `json:"url"`
        FileName string `json:"fileName"`
        SHA256   string `json:"sha256"`
    } `json:"payloads"`
    LocalizedResources []struct {
        Language string `json:"language"`
        License  string `json:"license"`
    } `json:"localizedResources"`
}

type manifest struct {
    ChannelItems []manifestItem `json:"channelItems"`
}

type vsPackage struct {
    ID         string `json:"id"`
    Language   string `json:"language,omitempty"`
    Payloads   []struct {
        URL      string `json:"url"`
        FileName string `json:"fileName"`
        SHA256   string `json:"sha256"`
    } `json:"payloads"`
    Dependencies map[string]interface{} `json:"dependencies,omitempty"`
}

func main() {
    // Parse arguments
    var args args
    flag.BoolVar(&args.showVersions, "show-versions", false, "Show available MSVC and Windows SDK versions")
    flag.BoolVar(&args.acceptLicense, "accept-license", false, "Automatically accept license")
    flag.StringVar(&args.msvcVersion, "msvc-version", "", "Get specific MSVC version")
    flag.StringVar(&args.sdkVersion, "sdk-version", "", "Get specific Windows SDK version")
    flag.BoolVar(&args.preview, "preview", false, "Use preview channel for Preview versions")
    flag.StringVar(&args.target, "target", DEFAULT_TARGET, fmt.Sprintf("Target architectures, comma separated (%s)", strings.Join(ALL_TARGETS, ",")))
    flag.StringVar(&args.host, "host", DEFAULT_HOST, fmt.Sprintf("Host architecture (%s)", strings.Join(ALL_HOSTS, ",")))
    flag.Parse()

    fmt.Printf("[INFO] Parsed arguments: show-versions=%v, accept-license=%v, msvc-version=%s, sdk-version=%s, preview=%v, host=%s, target=%s\n",
        args.showVersions, args.acceptLicense, args.msvcVersion, args.sdkVersion, args.preview, args.host, args.target)

    host := args.host
    targets := strings.Split(args.target, ",")
    for _, target := range targets {
        if !contains(ALL_TARGETS, target) {
            fmt.Fprintf(os.Stderr, "[ERROR] Unknown %s target architecture!\n", target)
            os.Exit(1)
        }
        fmt.Printf("[INFO] Validated target architecture: %s\n", target)
    }
    if !contains(ALL_HOSTS, host) {
        fmt.Fprintf(os.Stderr, "[ERROR] Unknown %s host architecture!\n", host)
        os.Exit(1)
    }
    fmt.Printf("[INFO] Validated host architecture: %s\n", host)

    // Convert OUTPUT to absolute path
    outputAbs, err := filepath.Abs(OUTPUT)
    if err != nil {
        fmt.Fprintf(os.Stderr, "[ERROR] Failed to get absolute path for %s: %v\n", OUTPUT, err)
        os.Exit(1)
    }
    fmt.Printf("[INFO] Using absolute output directory: %s\n", outputAbs)

    // Create output directory
    fmt.Printf("[INFO] Creating output directory: %s\n", outputAbs)
    if err := os.MkdirAll(outputAbs, 0755); err != nil {
        fmt.Fprintf(os.Stderr, "[ERROR] Failed to create %s: %v\n", outputAbs, err)
        os.Exit(1)
    }
    // Create downloads directory
    fmt.Printf("[INFO] Creating downloads directory: %s\n", DOWNLOADS)
    if err := os.MkdirAll(DOWNLOADS, 0755); err != nil {
        fmt.Fprintf(os.Stderr, "[ERROR] Failed to create %s: %v\n", DOWNLOADS, err)
        os.Exit(1)
    }

    // Get main manifest
    url := MANIFEST_URL
    if args.preview {
        url = MANIFEST_PREVIEW_URL
    }
    fmt.Printf("[INFO] Using manifest URL: %s\n", url)
    data, err := download(url)
    if err != nil {
        fmt.Fprintf(os.Stderr, "[ERROR] %v\n", err)
        os.Exit(1)
    }
    var manifest manifest
    fmt.Printf("[INFO] Parsing main manifest\n")
    if err := json.Unmarshal(data, &manifest); err != nil {
        fmt.Fprintf(os.Stderr, "[ERROR] Failed to parse manifest: %v\n", err)
        os.Exit(1)
    }
    fmt.Printf("[INFO] Parsed main manifest with %d channel items\n", len(manifest.ChannelItems))

    // Download VS manifest
    itemName := "Microsoft.VisualStudio.Manifests.VisualStudio"
    if args.preview {
        itemName = "Microsoft.VisualStudio.Manifests.VisualStudioPreview"
    }
    fmt.Printf("[INFO] Searching for manifest item: %s\n", itemName)
    vs, found := first(manifest.ChannelItems, func(x manifestItem) bool { return x.ID == itemName })
    if !found {
        fmt.Fprintf(os.Stderr, "[ERROR] %s not found in manifest\n", itemName)
        os.Exit(1)
    }
    fmt.Printf("[INFO] Found manifest item: %s\n", itemName)
    payload := vs.Payloads[0].URL
    fmt.Printf("[INFO] Downloading VS manifest from %s\n", payload)
    data, err = download(payload)
    if err != nil {
        fmt.Fprintf(os.Stderr, "[ERROR] %v\n", err)
        os.Exit(1)
    }
    var vsmanifest struct {
        Packages []vsPackage `json:"packages"`
    }
    fmt.Printf("[INFO] Parsing VS manifest\n")
    if err := json.Unmarshal(data, &vsmanifest); err != nil {
        fmt.Fprintf(os.Stderr, "[ERROR] Failed to parse VS manifest: %v\n", err)
        fmt.Fprintf(os.Stderr, "[DEBUG] VS manifest JSON: %s\n", string(data))
        os.Exit(1)
    }
    fmt.Printf("[INFO] Parsed VS manifest with %d packages\n", len(vsmanifest.Packages))

    // Find MSVC & WinSDK versions
    fmt.Printf("[INFO] Building package map\n")
    packages := make(map[string][]vsPackage)
    for _, p := range vsmanifest.Packages {
        pid := strings.ToLower(p.ID)
        packages[pid] = append(packages[pid], p)
    }
    fmt.Printf("[INFO] Found %d unique package IDs\n", len(packages))

    msvc := make(map[string]string)
    sdk := make(map[string]string)
    fmt.Printf("[INFO] Scanning for MSVC and Windows SDK versions\n")
    for pid := range packages {
        if matched, _ := regexp.MatchString(`^microsoft\.vc\..*\.tools\.hostx64\.targetx64\.base$`, pid); matched {
            parts := strings.Split(pid, ".")
            pver := strings.Join(parts[2:4], ".")
            if _, err := fmt.Sscanf(pver, "%d", new(int)); err == nil {
                msvc[pver] = pid
                fmt.Printf("[INFO] Found MSVC version: %s (%s)\n", pver, pid)
            }
        } else if matched, _ := regexp.MatchString(`^microsoft\.visualstudio\.component\.windows(10|11)sdk\.(\d+)$`, pid); matched {
            parts := strings.Split(pid, ".")
            pver := parts[len(parts)-1]
            if _, err := fmt.Sscanf(pver, "%d", new(int)); err == nil {
                sdk[pver] = pid
                fmt.Printf("[INFO] Found Windows SDK version: %s (%s)\n", pver, pid)
            }
        }
    }

    if args.showVersions {
        var msvcKeys, sdkKeys []string
        for k := range msvc {
            msvcKeys = append(msvcKeys, k)
        }
        for k := range sdk {
            sdkKeys = append(sdkKeys, k)
        }
        sort.Sort(sort.Reverse(sort.StringSlice(msvcKeys)))
        sort.Sort(sort.Reverse(sort.StringSlice(sdkKeys)))
        fmt.Println("MSVC versions:", strings.Join(msvcKeys, " "))
        fmt.Println("Windows SDK versions:", strings.Join(sdkKeys, " "))
        os.Exit(0)
    }

    msvcVer := args.msvcVersion
    if msvcVer == "" {
        var keys []string
        for k := range msvc {
            keys = append(keys, k)
        }
        sort.Sort(sort.Reverse(sort.StringSlice(keys)))
        msvcVer = keys[0]
        fmt.Printf("[INFO] Selected latest MSVC version: %s\n", msvcVer)
    }
    sdkVer := args.sdkVersion
    if sdkVer == "" {
        var keys []string
        for k := range sdk {
            keys = append(keys, k)
        }
        sort.Sort(sort.Reverse(sort.StringSlice(keys)))
        sdkVer = keys[0]
        fmt.Printf("[INFO] Selected latest Windows SDK version: %s\n", sdkVer)
    }

    if pid, ok := msvc[msvcVer]; ok {
        parts := strings.Split(pid, ".")
        msvcVer = strings.Join(parts[2:6], ".")
        fmt.Printf("[INFO] Adjusted MSVC version to full format: %s\n", msvcVer)
    } else {
        fmt.Fprintf(os.Stderr, "[ERROR] Unknown MSVC version: %s\n", args.msvcVersion)
        os.Exit(1)
    }
    if _, ok := sdk[sdkVer]; !ok {
        fmt.Fprintf(os.Stderr, "[ERROR] Unknown Windows SDK version: %s\n", args.sdkVersion)
        os.Exit(1)
    }

    fmt.Printf("[INFO] Proceeding to download MSVC v%s and Windows SDK v%s\n", msvcVer, sdkVer)

    // License agreement
    fmt.Printf("[INFO] Checking for BuildTools license\n")
    tools, found := first(manifest.ChannelItems, func(x manifestItem) bool { return x.ID == "Microsoft.VisualStudio.Product.BuildTools" })
    if !found {
        fmt.Fprintln(os.Stderr, "[ERROR] BuildTools not found")
        os.Exit(1)
    }
    fmt.Printf("[INFO] Found BuildTools item\n")
    resource, found := first(tools.LocalizedResources, func(x struct {
        Language string `json:"language"`
        License  string `json:"license"`
    }) bool { return x.Language == "en-us" })
    if !found {
        fmt.Fprintln(os.Stderr, "[ERROR] en-us license not found")
        os.Exit(1)
    }
    license := resource.License
    fmt.Printf("[INFO] Found license at %s\n", license)

    if !args.acceptLicense {
        fmt.Printf("Do you accept Visual Studio license at %s [Y/N] ? ", license)
        var accept string
        fmt.Scanln(&accept)
        if len(accept) == 0 || strings.ToLower(accept[0:1]) != "y" {
            fmt.Printf("[INFO] License not accepted, exiting\n")
            os.Exit(0)
        }
        fmt.Printf("[INFO] License accepted\n")
    } else {
        fmt.Printf("[INFO] License automatically accepted via --accept-license\n")
    }

    // Download MSVC
    fmt.Printf("[INFO] Preparing MSVC packages\n")
    msvcPackages := []string{
        "microsoft.visualcpp.dia.sdk",
        fmt.Sprintf("microsoft.vc.%s.crt.headers.base", msvcVer),
        fmt.Sprintf("microsoft.vc.%s.crt.source.base", msvcVer),
        fmt.Sprintf("microsoft.vc.%s.asan.headers.base", msvcVer),
        fmt.Sprintf("microsoft.vc.%s.pgo.headers.base", msvcVer),
    }
    for _, target := range targets {
        fmt.Printf("[INFO] Adding MSVC packages for target: %s\n", target)
        msvcPackages = append(msvcPackages,
            fmt.Sprintf("microsoft.vc.%s.tools.host%s.target%s.base", msvcVer, host, target),
            fmt.Sprintf("microsoft.vc.%s.tools.host%s.target%s.res.base", msvcVer, host, target),
            fmt.Sprintf("microsoft.vc.%s.crt.%s.desktop.base", msvcVer, target),
            fmt.Sprintf("microsoft.vc.%s.crt.%s.store.base", msvcVer, target),
            fmt.Sprintf("microsoft.vc.%s.premium.tools.host%s.target%s.base", msvcVer, host, target),
            fmt.Sprintf("microsoft.vc.%s.pgo.%s.base", msvcVer, target),
        )
        if contains([]string{"x86", "x64"}, target) {
            msvcPackages = append(msvcPackages, fmt.Sprintf("microsoft.vc.%s.asan.%s.base", msvcVer, target))
            fmt.Printf("[INFO] Added ASAN package for %s\n", target)
        }
        redistSuffix := ""
        if target == "arm" {
            redistSuffix = ".onecore.desktop"
        }
        redistPkg := fmt.Sprintf("microsoft.vc.%s.crt.redist.%s%s.base", msvcVer, target, redistSuffix)
        fmt.Printf("[INFO] Checking redist package: %s\n", redistPkg)
        if _, ok := packages[redistPkg]; !ok {
            redistName := fmt.Sprintf("microsoft.visualcpp.crt.redist.%s%s", target, redistSuffix)
            fmt.Printf("[INFO] Falling back to redist name: %s\n", redistName)
            redist, ok := packages[redistName]
            if ok && len(redist) > 0 {
                for depName := range redist[0].Dependencies {
                    if strings.HasSuffix(strings.ToLower(depName), ".base") {
                        redistPkg = strings.ToLower(depName)
                        fmt.Printf("[INFO] Selected dependency redist package: %s\n", redistPkg)
                        break
                    }
                    // Debug: Log dependency structure
                    depValue, _ := json.MarshalIndent(redist[0].Dependencies[depName], "", "  ")
                    fmt.Fprintf(os.Stderr, "[DEBUG] Dependency %s: %s\n", depName, string(depValue))
                }
            }
        }
        msvcPackages = append(msvcPackages, redistPkg)
    }

    fmt.Printf("[INFO] Processing %d MSVC packages\n", len(msvcPackages))
    for _, pkg := range msvcPackages {
        fmt.Printf("[INFO] Processing package: %s\n", pkg)
        pkgs, ok := packages[pkg]
        if !ok {
            fmt.Printf("[INFO] %s ... !!! MISSING !!!\n", pkg)
            continue
        }
        p, found := first(pkgs, func(p vsPackage) bool { return p.Language == "" || p.Language == "en-US" })
        if !found {
            fmt.Printf("[INFO] %s ... !!! NO MATCHING PACKAGE !!!\n", pkg)
            continue
        }
        fmt.Printf("[INFO] Found matching package: %s (language: %s)\n", p.ID, p.Language)
        for _, payload := range p.Payloads {
            filename := payload.FileName
            fmt.Printf("[INFO] Downloading payload: %s\n", filename)
            data, err := downloadProgress(payload.URL, payload.SHA256, filename)
            if err != nil {
                fmt.Fprintf(os.Stderr, "[ERROR] %v\n", err)
                os.Exit(1)
            }
            fmt.Printf("[INFO] Extracting zip: %s\n", filename)
            r, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
            if err != nil {
                fmt.Fprintf(os.Stderr, "[ERROR] Failed to read zip %s: %v\n", filename, err)
                os.Exit(1)
            }
            for _, f := range r.File {
                if strings.HasPrefix(f.Name, "Contents/") {
                    out := filepath.Join(outputAbs, strings.TrimPrefix(f.Name, "Contents/"))
                    fmt.Printf("[INFO] Extracting file: %s to %s\n", f.Name, out)
                    if err := os.MkdirAll(filepath.Dir(out), 0755); err != nil {
                        fmt.Fprintf(os.Stderr, "[ERROR] Failed to create dir for %s: %v\n", out, err)
                        os.Exit(1)
                    }
                    dst, err := os.Create(out)
                    if err != nil {
                        fmt.Fprintf(os.Stderr, "[ERROR] Failed to create %s: %v\n", out, err)
                        os.Exit(1)
                    }
                    src, err := f.Open()
                    if err != nil {
                        dst.Close()
                        fmt.Fprintf(os.Stderr, "[ERROR] Failed to open zip entry %s: %v\n", f.Name, err)
                        os.Exit(1)
                    }
                    if _, err := io.Copy(dst, src); err != nil {
                        src.Close()
                        dst.Close()
                        fmt.Fprintf(os.Stderr, "[ERROR] Failed to write %s: %v\n", out, err)
                        os.Exit(1)
                    }
                    src.Close()
                    dst.Close()
                    fmt.Printf("[INFO] Extracted %s\n", out)
                }
            }
        }
    }

    // Download Windows SDK
    fmt.Printf("[INFO] Preparing Windows SDK packages\n")
    sdkPackages := []string{
        "Windows SDK for Windows Store Apps Tools-x86_en-us.msi",
        "Windows SDK for Windows Store Apps Headers-x86_en-us.msi",
        "Windows SDK for Windows Store Apps Headers OnecoreUap-x86_en-us.msi",
        "Windows SDK for Windows Store Apps Libs-x86_en-us.msi",
        "Universal CRT Headers Libraries and Sources-x86_en-us.msi",
    }
    for _, target := range ALL_TARGETS {
        sdkPackages = append(sdkPackages,
            fmt.Sprintf("Windows SDK Desktop Headers %s-x86_en-us.msi", target),
            fmt.Sprintf("Windows SDK OnecoreUap Headers %s-x86_en-us.msi", target),
        )
        fmt.Printf("[INFO] Added SDK header packages for target: %s\n", target)
    }
    for _, target := range targets {
        sdkPackages = append(sdkPackages, fmt.Sprintf("Windows SDK Desktop Libs %s-x86_en-us.msi", target))
        fmt.Printf("[INFO] Added SDK libs package for target: %s\n", target)
    }

    fmt.Printf("[INFO] Creating temporary directory for SDK\n")
    tempDir, err := os.MkdirTemp(DOWNLOADS, "tmp")
    if err != nil {
        fmt.Fprintf(os.Stderr, "[ERROR] Failed to create temp dir: %v\n", err)
        os.Exit(1)
    }
    defer os.RemoveAll(tempDir)
    fmt.Printf("[INFO] Created temporary directory: %s\n", tempDir)

    fmt.Printf("[INFO] Selecting SDK package for version: %s\n", sdkVer)
    sdkPkg := packages[sdk[sdkVer]][0]
    var deps []string
    for depName := range sdkPkg.Dependencies {
        deps = append(deps, depName)
    }
    if len(deps) == 0 {
        fmt.Fprintf(os.Stderr, "[ERROR] No dependencies found for SDK package %s\n", sdk[sdkVer])
        os.Exit(1)
    }
    fmt.Printf("[INFO] Found %d dependencies for SDK package\n", len(deps))
    depID := strings.ToLower(deps[0])
    if _, ok := packages[depID]; !ok {
        fmt.Fprintf(os.Stderr, "[ERROR] Dependency %s not found in packages\n", depID)
        os.Exit(1)
    }
    sdkPkg = packages[depID][0]
    fmt.Printf("[INFO] Selected SDK dependency package: %s\n", depID)

    var msi, cabs []string
    fmt.Printf("[INFO] Processing %d SDK packages\n", len(sdkPackages))
    for _, pkg := range sdkPackages {
        fmt.Printf("[INFO] Checking SDK package: %s\n", pkg)
        var payload *struct {
            URL      string `json:"url"`
            FileName string `json:"fileName"`
            SHA256   string `json:"sha256"`
        }
        for _, p := range sdkPkg.Payloads {
            if p.FileName == "Installers\\"+pkg {
                payload = &p
                break
            }
        }
        if payload == nil {
            fmt.Printf("[INFO] Skipping SDK package %s (no payload found)\n", pkg)
            continue
        }
        fpath := filepath.Join(DOWNLOADS, pkg)
        fmt.Printf("[INFO] Downloading SDK package: %s\n", pkg)
        data, err := downloadProgress(payload.URL, payload.SHA256, pkg)
        if err != nil {
            fmt.Fprintf(os.Stderr, "[ERROR] %v\n", err)
            os.Exit(1)
        }
        fmt.Printf("[INFO] Processing MSI for .cab references: %s\n", pkg)
        msi = append(msi, fpath)
        fmt.Printf("[INFO] Added MSI file: %s\n", fpath)
        cabs = append(cabs, getMsiCabs(data)...)
    }

    fmt.Printf("[INFO] Processing %d .cab files\n", len(cabs))
    for _, pkg := range cabs {
        fmt.Printf("[INFO] Checking .cab package: %s\n", pkg)
        var payload *struct {
            URL      string `json:"url"`
            FileName string `json:"fileName"`
            SHA256   string `json:"sha256"`
        }
        for _, p := range sdkPkg.Payloads {
            if p.FileName == "Installers\\"+pkg {
                payload = &p
                break
            }
        }
        if payload == nil {
            fmt.Printf("[INFO] Skipping .cab package %s (no payload found)\n", pkg)
            continue
        }
        fmt.Printf("[INFO] Downloading .cab package: %s\n", pkg)
        if _, err := downloadProgress(payload.URL, payload.SHA256, pkg); err != nil {
            fmt.Fprintf(os.Stderr, "[ERROR] %v\n", err)
            os.Exit(1)
        }
    }

    fmt.Printf("[INFO] Unpacking %d MSI files\n", len(msi))
    for _, m := range msi {
        fmt.Printf("[INFO] Unpacking MSI: %s\n", m)
        logFile := filepath.Join(DOWNLOADS, fmt.Sprintf("%s.log", filepath.Base(m)))
        cmd := exec.Command("msiexec.exe", "/a", m, "/quiet", "/qn", fmt.Sprintf("TARGETDIR=%s", outputAbs), "/lv*", logFile)
        cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
        fmt.Printf("[INFO] Running command: %s\n", strings.Join(cmd.Args, " "))
        output, err := cmd.CombinedOutput()
        if err != nil {
            fmt.Fprintf(os.Stderr, "[WARNING] Failed to unpack %s: %v\n", m, err)
            fmt.Fprintf(os.Stderr, "[WARNING] msiexec output: %s\n", string(output))
            fmt.Fprintf(os.Stderr, "[WARNING] See log file for details: %s\n", logFile)
            fmt.Printf("[INFO] Continuing with next MSI\n")
            continue
        }
        fmt.Printf("[INFO] Unpacked MSI: %s\n", m)
        tempMsi := filepath.Join(outputAbs, filepath.Base(m))
        fmt.Printf("[INFO] Removing temporary MSI copy: %s\n", tempMsi)
        if err := os.Remove(tempMsi); err != nil {
            fmt.Fprintf(os.Stderr, "[WARNING] Failed to remove %s: %v\n", tempMsi, err)
        }
    }

    // Get versions
    fmt.Printf("[INFO] Reading MSVC version\n")
    msvcDir, err := os.ReadDir(filepath.Join(outputAbs, "VC", "Tools", "MSVC"))
    if err != nil {
        fmt.Fprintf(os.Stderr, "[ERROR] Failed to read MSVC dir: %v\n", err)
        os.Exit(1)
    }
    msvcv := msvcDir[0].Name()
    fmt.Printf("[INFO] MSVC version: %s\n", msvcv)
    fmt.Printf("[INFO] Reading Windows SDK version\n")
    sdkDir, err := os.ReadDir(filepath.Join(outputAbs, "Windows Kits", "10", "bin"))
    if err != nil {
        fmt.Fprintf(os.Stderr, "[ERROR] Failed to read SDK bin dir: %v\n", err)
        os.Exit(1)
    }
    sdkv := sdkDir[0].Name()
    fmt.Printf("[INFO] Windows SDK version: %s\n", sdkv)

    // Handle debug CRT runtime files
    redist := filepath.Join(outputAbs, "VC", "Redist")
    fmt.Printf("[INFO] Checking for redist directory: %s\n", redist)
    if _, err := os.Stat(redist); err == nil {
        fmt.Printf("[INFO] Reading redist MSVC directory\n")
        redistDir, err := os.ReadDir(filepath.Join(redist, "MSVC"))
        if err != nil {
            fmt.Fprintf(os.Stderr, "[ERROR] Failed to read redist MSVC dir: %v\n", err)
            os.Exit(1)
        }
        redistv := redistDir[0].Name()
        fmt.Printf("[INFO] Redist version: %s\n", redistv)
        src := filepath.Join(redist, "MSVC", redistv, "debug_nonredist")
        for _, target := range targets {
            fmt.Printf("[INFO] Moving debug DLLs for target: %s\n", target)
            dst := filepath.Join(outputAbs, "VC", "Tools", "MSVC", msvcv, "bin", "Host"+host, target)
            err := filepath.Walk(filepath.Join(src, target), func(path string, info os.FileInfo, err error) error {
                if err != nil {
                    return err
                }
                if !info.IsDir() && strings.HasSuffix(strings.ToLower(info.Name()), ".dll") {
                    rel, err := filepath.Rel(src, path)
                    if err != nil {
                        return err
                    }
                    dstPath := filepath.Join(dst, filepath.Base(rel))
                    fmt.Printf("[INFO] Moving DLL: %s to %s\n", path, dstPath)
                    if err := os.MkdirAll(filepath.Dir(dstPath), 0755); err != nil {
                        return err
                    }
                    return os.Rename(path, dstPath)
                }
                return nil
            })
            if err != nil {
                fmt.Fprintf(os.Stderr, "[ERROR] Failed to move debug DLLs: %v\n", err)
                os.Exit(1)
            }
        }
        fmt.Printf("[INFO] Removing redist directory: %s\n", redist)
        os.RemoveAll(redist)
    } else {
        fmt.Printf("[INFO] No redist directory found, skipping\n")
    }

    // Copy msdia140.dll
    msdia140dll := map[string]string{
        "x86":   "msdia140.dll",
        "x64":   "amd64/msdia140.dll",
        "arm":   "arm/msdia140.dll",
        "arm64": "arm64/msdia140.dll",
    }
    dst := filepath.Join(outputAbs, "VC", "Tools", "MSVC", msvcv, "bin", "Host"+host)
    src := filepath.Join(outputAbs, "DIA%20SDK", "bin", msdia140dll[host])
    fmt.Printf("[INFO] Copying msdia140.dll from %s\n", src)
    for _, target := range targets {
        dstPath := filepath.Join(dst, target, filepath.Base(msdia140dll[host]))
        fmt.Printf("[INFO] Copying msdia140.dll to %s\n", dstPath)
        if err := os.MkdirAll(filepath.Dir(dstPath), 0755); err != nil {
            fmt.Fprintf(os.Stderr, "[ERROR] Failed to create dir for %s: %v\n", dstPath, err)
            os.Exit(1)
        }
        data, err := os.ReadFile(src)
        if err != nil {
            fmt.Fprintf(os.Stderr, "[ERROR] Failed to read %s: %v\n", src, err)
            os.Exit(1)
        }
        if err := os.WriteFile(dstPath, data, 0644); err != nil {
            fmt.Fprintf(os.Stderr, "[ERROR] Failed to write %s: %v\n", dstPath, err)
            os.Exit(1)
        }
    }
    fmt.Printf("[INFO] Removing DIA SDK directory: %s\n", filepath.Join(outputAbs, "DIA%20SDK"))
    os.RemoveAll(filepath.Join(outputAbs, "DIA%20SDK"))

    // Cleanup
    fmt.Printf("[INFO] Performing cleanup\n")
    for _, path := range []string{
        filepath.Join(outputAbs, "Common7"),
        filepath.Join(outputAbs, "VC", "Tools", "MSVC", msvcv, "Auxiliary"),
    } {
        fmt.Printf("[INFO] Removing directory: %s\n", path)
        os.RemoveAll(path)
    }
    for _, target := range targets {
        for _, f := range []string{"store", "uwp", "enclave", "onecore"} {
            path := filepath.Join(outputAbs, "VC", "Tools", "MSVC", msvcv, "lib", target, f)
            fmt.Printf("[INFO] Removing directory: %s\n", path)
            os.RemoveAll(path)
        }
        path := filepath.Join(outputAbs, "VC", "Tools", "MSVC", msvcv, "bin", "Host"+host, target, "onecore")
        fmt.Printf("[INFO] Removing directory: %s\n", path)
        os.RemoveAll(path)
    }
    for _, f := range []string{
        "Catalogs",
        "DesignTime",
        fmt.Sprintf("bin/%s/chpe", sdkv),
        fmt.Sprintf("Lib/%s/ucrt_enclave", sdkv),
    } {
        path := filepath.Join(outputAbs, "Windows Kits", "10", f)
        fmt.Printf("[INFO] Removing directory: %s\n", path)
        os.RemoveAll(path)
    }
    for _, arch := range []string{"x86", "x64", "arm", "arm64"} {
        if !contains(targets, arch) {
            path := filepath.Join(outputAbs, "Windows Kits", "10", "Lib", sdkv, "ucrt", arch)
            fmt.Printf("[INFO] Removing directory: %s\n", path)
            os.RemoveAll(path)
            path = filepath.Join(outputAbs, "Windows Kits", "10", "Lib", sdkv, "um", arch)
            fmt.Printf("[INFO] Removing directory: %s\n", path)
            os.RemoveAll(path)
        }
        if arch != host {
            path := filepath.Join(outputAbs, "VC", "Tools", "MSVC", msvcv, "bin", "Host"+arch)
            fmt.Printf("[INFO] Removing directory: %s\n", path)
            os.RemoveAll(path)
            path = filepath.Join(outputAbs, "Windows Kits", "10", "bin", sdkv, arch)
            fmt.Printf("[INFO] Removing directory: %s\n", path)
            os.RemoveAll(path)
        }
    }
    for _, target := range targets {
        path := filepath.Join(outputAbs, "VC", "Tools", "MSVC", msvcv, "bin", "Host"+host, target, "vctip.exe")
        fmt.Printf("[INFO] Removing file: %s\n", path)
        os.Remove(path)
    }

    // Extra files for nvcc
    build := filepath.Join(outputAbs, "VC", "Auxiliary", "Build")
    fmt.Printf("[INFO] Creating directory for nvcc files: %s\n", build)
    if err := os.MkdirAll(build, 0755); err != nil {
        fmt.Fprintf(os.Stderr, "[ERROR] Failed to create %s: %v\n", build, err)
        os.Exit(1)
    }
    fmt.Printf("[INFO] Writing vcvarsall.bat\n")
    if err := os.WriteFile(filepath.Join(build, "vcvarsall.bat"), []byte("rem both bat files are here only for nvcc, do not call them manually"), 0644); err != nil {
        fmt.Fprintf(os.Stderr, "[ERROR] Failed to write vcvarsall.bat: %v\n", err)
        os.Exit(1)
    }
    fmt.Printf("[INFO] Writing vcvars64.bat\n")
    if err := os.WriteFile(filepath.Join(build, "vcvars64.bat"), nil, 0644); err != nil {
        fmt.Fprintf(os.Stderr, "[ERROR] Failed to write vcvars64.bat: %v\n", err)
        os.Exit(1)
    }

    // Setup.bat
    fmt.Printf("[INFO] Generating setup scripts\n")
    for _, target := range targets {
        setup := fmt.Sprintf(`@echo off

set VSCMD_ARG_HOST_ARCH=%s
set VSCMD_ARG_TGT_ARCH=%s

set VCToolsVersion=%s
set WindowsSDKVersion=%s\

set VCToolsInstallDir=%%~dp0VC\Tools\MSVC\%s\
set WindowsSdkBinPath=%%~dp0Windows Kits\10\bin\

set PATH=%%~dp0VC\Tools\MSVC\%s\bin\Host%s\%s;%%~dp0Windows Kits\10\bin\%s\%s;%%~dp0Windows Kits\10\bin\%s\%s\ucrt;%%PATH%%
set INCLUDE=%%~dp0VC\Tools\MSVC\%s\include;%%~dp0Windows Kits\10\Include\%s\ucrt;%%~dp0Windows Kits\10\Include\%s\shared;%%~dp0Windows Kits\10\Include\%s\um;%%~dp0Windows Kits\10\Include\%s\winrt;%%~dp0Windows Kits\10\Include\%s\cppwinrt
set LIB=%%~dp0VC\Tools\MSVC\%s\lib\%s;%%~dp0Windows Kits\10\Lib\%s\ucrt\%s;%%~dp0Windows Kits\10\Lib\%s\um\%s
`, host, target, msvcv, sdkv, msvcv, msvcv, host, target, sdkv, host, sdkv, host, msvcv, sdkv, sdkv, sdkv, sdkv, sdkv, msvcv, target, sdkv, target, sdkv, target)
        setupPath := filepath.Join(outputAbs, fmt.Sprintf("setup_%s.bat", target))
        fmt.Printf("[INFO] Writing setup script: %s\n", setupPath)
        if err := os.WriteFile(setupPath, []byte(setup), 0644); err != nil {
            fmt.Fprintf(os.Stderr, "[ERROR] Failed to write %s: %v\n", setupPath, err)
            os.Exit(1)
        }
    }

    fmt.Printf("[INFO] Total downloaded: %d MB\n", totalDownload>>20)
    fmt.Println("[INFO] Done!")
}