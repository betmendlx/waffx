# Advanced WAF Detection Tool

This tool is designed to detect the presence of Web Application Firewalls (WAFs) on web applications by using a set of attack vectors. It performs normal and attack requests to identify differences in responses, indicating the presence of WAFs.

## Features

- Detects various WAFs such as Cloudflare, Incapsula, ModSecurity, and more.
- Supports multiple input formats (text, CSV, JSON) for target URLs.
- Concurrent requests for faster detection.
- Customizable attack vectors via YAML file.

## Requirements

- Python 3.7+
- aiohttp
- aiohttp_retry
- PyYAML
- python-dotenv

## Installation

1. Clone the repository:
    ```bash
    git clone https://github.com/betmendlx/waffx.git
    cd waf-detection-tool
    ```

2. Install the required packages:
    ```bash
    pip install -r requirements.txt
    ```

## Usage

### Command-line Options

- `-u, --url`: Single URL to check.
- `-i, --input-file`: Input file containing URLs (text, CSV, or JSON).
- `--timeout`: Timeout between requests in seconds (default: 10).
- `--output`: Output results to a file.
- `--concurrency`: Number of concurrent requests (default: 3).

### Examples

1. **Single URL**:
    ```bash
    python waff.py -u http://example.com
    ```

2. **Multiple URLs from a file**:
    ```bash
    python waff.py -i targets.txt
    ```

3. **Output results to a file**:
    ```bash
    python waff.py -i targets.txt --output results.json
    ```

## Attack Vectors

The tool uses predefined attack vectors stored in `attack_vectors.yaml`. If the file is not found or fails to load, it falls back to the default vectors.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
