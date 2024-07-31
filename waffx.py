import argparse
import asyncio
import aiohttp
import csv
import json
import logging
import random
import string
import os
import yaml
import re
from urllib.parse import urlparse
from aiohttp import TCPConnector
from aiohttp_retry import RetryClient, ExponentialRetry
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Setting up logging
logging.basicConfig(format='%(asctime)s - %(name)s - %(levelname)s - %(message)s', level=logging.INFO)
logger = logging.getLogger('waf_detector')

# Default attack vectors (fallback if YAML loading fails)
DEFAULT_ATTACK_VECTORS = {
    'xss': '<script>alert("XSS");</script>',
    'sqli': "UNION SELECT ALL FROM information_schema AND ' or SLEEP(5) or '",
    'lfi': '../../../../etc/passwd',
    'rce': '/bin/cat /etc/passwd; ping 127.0.0.1; curl google.com',
    'xxe': '<!ENTITY xxe SYSTEM "file:///etc/shadow">]><pwn>&hack;</pwn>'
}

# WAF signatures
WAF_SIGNATURES = {
    'Cloudflare': r'cloudflare|cf-ray',
    'Incapsula': r'incap_ses|visid_incap',
    'ModSecurity': r'mod_security|NOYB',
    'Akamai': r'AkamaiGHost',
    'F5 BIG-IP': r'BigIP|F5\-TrafficShield',
    'Barracuda': r'barracuda_',
    'AWS WAF': r'aws-waf',
    'Wordfence': r'wordfence',
    'Sucuri': r'sucuri',
}

def create_random_param_name(length=10):
    return ''.join(random.choice(string.ascii_lowercase) for _ in range(length))

def read_targets(file_path):
    targets = []
    try:
        if file_path.endswith('.csv'):
            with open(file_path, newline='') as csvfile:
                reader = csv.DictReader(csvfile)
                targets = [row['url'] for row in reader]
        elif file_path.endswith('.json'):
            with open(file_path) as jsonfile:
                data = json.load(jsonfile)
                targets = [entry['url'] for entry in data]
        else:
            with open(file_path) as txtfile:
                targets = txtfile.read().splitlines()
    except Exception as e:
        logger.error(f"Error reading targets from file {file_path}: {e}")
    return targets

def normalize_url(url):
    if not urlparse(url).scheme:
        url = 'http://' + url
    return url

def is_valid_url(url):
    parsed = urlparse(url)
    return bool(parsed.scheme and parsed.netloc)

def is_valid_file_path(file_path):
    return os.path.isfile(file_path)

def load_attack_vectors(file_path='attack_vectors.yaml'):
    try:
        with open(file_path, 'r') as file:
            return yaml.safe_load(file)
    except Exception as e:
        logger.error(f"Error loading attack vectors: {e}")
        return DEFAULT_ATTACK_VECTORS

async def make_request(session, url, headers=None, params=None):
    try:
        async with session.get(url, headers=headers, params=params, timeout=15) as response:
            return await response.text(), response.status, response.headers
    except asyncio.TimeoutError:
        logger.error(f"Request timed out for {url}")
        raise
    except aiohttp.ClientError as e:
        logger.error(f"Client error for {url}: {e}")
        raise
    except Exception as e:
        logger.error(f"Unexpected error for {url}: {e}")
        raise

async def attack(url, vector, session):
    params = {create_random_param_name(): vector}
    return await make_request(session, url, params=params)

def detect_waf_signature(response_headers, response_body):
    detected_wafs = []
    
    headers_str = ' '.join(f"{k}: {v}" for k, v in response_headers.items()).lower()
    
    for waf, pattern in WAF_SIGNATURES.items():
        if re.search(pattern, headers_str, re.IGNORECASE) or re.search(pattern, response_body, re.IGNORECASE):
            detected_wafs.append(waf)
    
    return detected_wafs

async def detect_waf(url, session, attack_vectors):
    url = normalize_url(url)
    logger.info(f"[*] Checking {url}")

    try:
        normal_resp, normal_status, normal_headers = await make_request(session, url)
        logger.info(f"[+] Normal request successful for {url}. Status: {normal_status}")
    except Exception as e:
        logger.warning(f"[-] Normal request failed for {url}: {e}")
        return None, []

    for attack_name, vector in attack_vectors.items():
        try:
            attack_resp, attack_status, attack_headers = await attack(url, vector, session)
            logger.info(f"[+] Attack request ({attack_name}) successful for {url}. Status: {attack_status}")
        except Exception as e:
            logger.warning(f"[-] Attack request ({attack_name}) failed for {url}: {e}")
            continue

        detected_wafs = detect_waf_signature(attack_headers, attack_resp)
        if normal_status != attack_status or detected_wafs:
            logger.info(f"[+] WAF detected at {url} using {attack_name} vector")
            logger.info(f"    Normal response code: {normal_status}")
            logger.info(f"    Attack response code: {attack_status}")
            logger.info(f"    Detected WAFs: {', '.join(detected_wafs)}")
            return url, detected_wafs

    logger.info(f"[-] No WAF detected at {url}")
    return None, []

async def main(target=None, input_file=None, timeout=10, output_file=None, concurrency=3):
    if input_file:
        targets = read_targets(input_file)
    else:
        targets = [target]

    detected_wafs = []
    
    connector = TCPConnector(limit=concurrency, force_close=True)
    retry_options = ExponentialRetry(attempts=3)
    
    attack_vectors = load_attack_vectors()

    async with RetryClient(connector=connector, retry_options=retry_options) as session:
        tasks = [detect_waf(url, session, attack_vectors) for url in targets]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        for result in results:
            if isinstance(result, Exception):
                logger.error(f"Error occurred: {result}")
            elif result[0]:  # If WAF detected
                detected_wafs.append(result)

    output = '\n'.join(f"{url}: {', '.join(wafs)}" for url, wafs in detected_wafs)
    print(output)

    if output_file:
        with open(output_file, 'w') as f:
            json.dump(detected_wafs, f, indent=4)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Advanced WAF detection tool")
    parser.add_argument("-u", "--url", help="Single URL to check")
    parser.add_argument("-i", "--input-file", help="Input file containing URLs (text, csv, or json)")
    parser.add_argument("--timeout", type=int, default=10, help="Timeout between requests in seconds")
    parser.add_argument("--output", help="Output results to a file")
    parser.add_argument("--concurrency", type=int, default=3, help="Number of concurrent requests")

    args = parser.parse_args()

    if not args.url and not args.input_file:
        parser.error("Either --url or --input-file must be specified")

    asyncio.run(main(target=args.url, input_file=args.input_file, timeout=args.timeout, output_file=args.output, concurrency=args.concurrency))
