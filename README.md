# TrivyScan

A high-performance, concurrent container image vulnerability scanner with professional HTML reports.

## Features

- 🚀 **Concurrent Scanning** - Scan multiple images simultaneously
- 📊 **Beautiful Reports** - Sentra-inspired interactive HTML reports
- 🔄 **Auto Updates** - Automatic vulnerability database updates
- 📦 **Single Binary** - Self-contained with embedded templates
- 🎯 **Smart Filtering** - Filter by severity levels
- 🔒 **Thread-Safe** - Deadlock-free concurrent processing

## Installation

### Prerequisites

- [Trivy](https://aquasecurity.github.io/trivy/) v0.70.0+

### Install TrivyScan

#### Go

```bash
go install github.com/anhnmt/trivyscan@latest
```

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

# Scan multiple images
trivyscan -i image1.tar,image2.tar,image3.tar -o ./reports

# Scan folder (all .tar files)
trivyscan -i ./images -o ./reports

# Custom configuration
trivyscan -i app.tar -o ./reports -c 5 -s CRITICAL,HIGH
```

## Usage

```bash
trivyscan [flags]
```

### Flags

| Flag | Short | Description | Default |
|------|-------|-------------|---------|
| `--input` | `-i` | Input image file, comma-separated files, or directory | *required* |
| `--output` | `-o` | Output directory for reports | `.` |
| `--concurrency` | `-c` | Number of concurrent workers | `3` |
| `--severity` | `-s` | Severity levels to scan | `MEDIUM,HIGH,CRITICAL` |
| `--skip-db-update` | `-u` | Skip database update | `false` |
| `--skip-trivy-check` | `-t` | Skip Trivy installation check | `false` |

## Examples

### Basic Scan

```bash
trivyscan -i myapp.tar -o ./reports
```

### High-Priority Vulnerabilities Only

```bash
trivyscan -i production.tar -o ./reports -s CRITICAL,HIGH
```

### Batch Scanning with High Concurrency

```bash
trivyscan -i *.tar -o ./reports -c 10
```

### Scan Folder (all .tar files)

```bash
trivyscan -i ./images -o ./reports
```

### CI/CD (Skip DB Update)

```bash
trivyscan -i app.tar -o ./reports -u -s CRITICAL,HIGH
```

## Output

Reports are generated with the format: `{basename}-{hash}-report.html`

**Example:**
```
./reports/
├── nginx-a3f9c2-report.html
├── api-server-7b8d1e-report.html
└── frontend-5e2f4a-report.html
```

The 6-character hash ensures unique filenames for each scan.

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
    path: ./reports/*.html
```

### GitLab CI

```yaml
security-scan:
  script:
    - go install github.com/anhnmt/trivyscan@latest
    - trivyscan -i image.tar -o ./reports -s CRITICAL,HIGH
  artifacts:
    paths:
      - ./reports/*.html
```

## Performance Tips

| CPU Cores | Recommended Workers |
|-----------|---------------------|
| 2-4 | 2-3 |
| 4-8 | 3-5 |
| 8+ | 5-10 |

**Memory:** Each worker uses ~500MB-1GB during scanning

## Troubleshooting

### Trivy Not Found

```bash
# Install Trivy
curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin
```

### Database Update Failed

```bash
# Skip update if recently updated
trivyscan -i image.tar -o ./reports -u
```

### Out of Memory

```bash
# Reduce concurrency
trivyscan -i *.tar -o ./reports -c 2
```

## Report Features

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