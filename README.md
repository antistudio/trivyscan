# TrivyScan

A container image vulnerability scanner built on Trivy, with professional HTML reports and a multi-image summary.

## Features

- 📁 **Batch Scanning** - Scan a whole directory of `.tar`/`.tar.gz`/`.tgz` images in one command
- 📊 **Beautiful Reports** - Sentra-inspired interactive HTML report per image
- 📋 **Summary Page** - One `summary.html` with severity counts for every image
- 🗂️ **JSON First** - Raw Trivy JSON kept for every image; HTML is rendered from it
- ⚡ **Incremental** - Unchanged images are not rescanned until the Trivy DB changes
- 🔄 **Auto Updates** - Automatic vulnerability database updates
- 📦 **Single Binary** - Self-contained with embedded templates
- 🎯 **Smart Filtering** - Filter by severity levels without rescanning

## Installation

### Prerequisites

- [Trivy](https://aquasecurity.github.io/trivy/) v0.70.0+

### Install TrivyScan

#### Go (build from source)

```bash
go build -ldflags "-s -w -X main.version=$(git describe --tags --always)" -o trivyscan .
```

> **Note:** Without `-ldflags`, `trivyscan -v` will show `dev`. The version is injected at build time via linker flags.

#### Windows (one-liner)

Open PowerShell as **Administrator** and run:

```powershell
irm https://raw.githubusercontent.com/anhnmt/trivyscan/main/scripts/install.ps1 | iex
```

This downloads the latest release, installs Trivy + TrivyScan to `C:\Program Files\`, and adds both to `PATH`.

#### Linux / macOS

```bash
curl -fsSL https://raw.githubusercontent.com/anhnmt/trivyscan/main/scripts/install.sh | sudo bash
```

For manual installation and more details, see [INSTALL.md](INSTALL.md).

## Quick Start

```bash
# Scan single image
trivyscan -i nginx.tar -o ./reports

# Scan image references (local Docker/containerd/Podman, or pulled from the registry)
trivyscan -i nginx:latest,redis:7,ghcr.io/org/app:dev -o ./reports

# Scan images listed in a file (one per line, # comments allowed)
trivyscan -l images.txt -o ./reports

# Scan folder (all .tar/.tar.gz/.tgz files) → per-image reports + summary.html
trivyscan -i ./images -o ./reports

# Show only critical/high (re-renders from JSON, no rescan)
trivyscan -i ./images -o ./reports -s CRITICAL,HIGH
```

## Usage

```bash
trivyscan [flags]
```

### Flags

| Flag | Short | Description | Default |
|------|-------|-------------|---------|
| `--input` | `-i` | Image references, `.tar`/`.tar.gz`/`.tgz` files or directories; comma-separated or repeated | *required* (or `-l`) |
| `--list` | `-l` | File with one input per line (`#` comments allowed) | |
| `--output` | `-o` | Output directory (`json/`, `html/`, `summary.html`) | `.` |
| `--severity` | `-s` | Severity levels shown in reports (render-time filter) | all |
| `--scanner` | `-S` | Trivy scanners (`vuln,misconfig,secret,license`) | Trivy default |
| `--force` | `-f` | Rescan even if an up-to-date JSON report exists | `false` |
| `--timeout` | `-t` | Timeout per scan | `10m` |
| `--max-retries` | `-rt` | Max retry attempts for transient errors | `3` |
| `--max-depth` | `-md` | Max directory depth when scanning a folder | `5` |
| `--update` | `-u` | Only update the Trivy databases and exit | `false` |
| `--skip-db-update` | `-sd` | Skip database update | `false` |
| `--skip-trivy-check` | `-st` | Skip Trivy installation check | `false` |
| `--version` | `-v` | Show version | `false` |

## Examples

### Basic Scan

```bash
trivyscan -i myapp.tar -o ./reports
```

### High-Priority Vulnerabilities Only

```bash
trivyscan -i production.tar -o ./reports -s CRITICAL,HIGH
```

### Scan Folder (all .tar/.tar.gz/.tgz files)

```bash
trivyscan -i ./images -o ./reports
```

### Scan Image References

```bash
# Comma-separated, repeated -i, and a list file can be combined; duplicates are scanned once
trivyscan -i nginx:latest,app:dev -i registry.local:5000/team/api:1.4 -l images.txt -o ./reports
```

```
# images.txt
nginx:latest
redis:7-alpine          # cache
ghcr.io/org/app@sha256:<digest>
./exports/legacy.tar    # tar files and directories work here too
```

- Anything that is not an existing path and matches the Docker reference grammar
  (`[registry[:port]/]name[:tag][@digest]`, lowercase name) is treated as an image.
- Trivy looks for the image in Docker, containerd, Podman, then the remote registry.
  Private registries use your `docker login` credentials, or `TRIVY_USERNAME`/`TRIVY_PASSWORD`.
- Image references are always rescanned (a tag can move); only `.tar` inputs reuse an up-to-date JSON.
- An unknown tag/repository or a denied pull fails immediately instead of being retried.

### CI/CD (Skip DB Update)

```bash
trivyscan -i app.tar -o ./reports -sd -s CRITICAL,HIGH
```

## Output

Each image is scanned once by Trivy into JSON; the HTML pages are rendered from that JSON.

```
./reports/
├── summary.html                  # all images: OS, severity counts, link to detail page
├── json/
│   ├── nginx_a3f9c2.json         # full Trivy JSON (all severities)
│   └── api-server_7b8d1e.json
└── html/
    ├── nginx_a3f9c2.html         # detail report
    └── api-server_7b8d1e.html
```

- File names are `{basename}_{hash}`, where the 6-character hash is taken from the tar's content
  (or from the reference string for image references).
- JSON always contains every severity; `-s` only filters what the HTML pages show.
- On the next run, a tar whose JSON is newer than the Trivy DB is not rescanned, only re-rendered.
  Changing `-s` is therefore instant. Use `--force` to rescan anyway (e.g. after changing `-S`).
- `summary.html` also lists reports from earlier runs that are still in `json/`.
- `json/` and `html/` are output artifacts; add them to `.gitignore` if the output directory is inside a repository.

## CI/CD Integration

### GitHub Actions

```yaml
- name: Security Scan
  run: |
    go install github.com/anhnmt/trivyscan@latest
    trivyscan -i myapp.tar -o ./reports -s CRITICAL,HIGH
    
- name: Upload Reports
  uses: actions/upload-artifact@v3
  with:
    name: security-reports
    path: ./reports/
```

### GitLab CI

```yaml
security-scan:
  script:
    - go install github.com/anhnmt/trivyscan@latest
    - trivyscan -i image.tar -o ./reports -s CRITICAL,HIGH
  artifacts:
    paths:
      - ./reports/
```

## Troubleshooting

### Trivy Not Found

```bash
# Install Trivy
curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin
```

### Database Update Failed

```bash
# Skip update if recently updated
trivyscan -i image.tar -o ./reports -sd
```

### Scan Timeout on Large Images

```bash
trivyscan -i big-image.tar -o ./reports -t 30m
```

## Report Features

- ✅ Summary page across all scanned images
- ✅ Summary cards with vulnerability counts
- ✅ Collapsible sections by component
- ✅ Sortable tables (Severity → CVE → Package → Fix)
- ✅ Filter by severity dropdown
- ✅ Zebra-striped rows for readability
- ✅ Clickable CVE links and references
- ✅ Responsive design (desktop/mobile)

## License

MIT License

## Author

[anhnmt](https://github.com/anhnmt)