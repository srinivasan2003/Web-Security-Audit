import asyncio
import aiohttp
from termcolor import colored
from urllib.parse import urlparse

SECURITY_HEADERS = {
    "Strict-Transport-Security": "Enforces secure (HTTP over SSL/TLS) connections to the server.",
    "Content-Security-Policy": "Helps prevent cross-site scripting (XSS) and other code injection attacks.",
    "X-Content-Type-Options": "Prevents MIME type sniffing.",
    "X-Frame-Options": "Protects against clickjacking.",
    "X-XSS-Protection": "Protects against XSS attacks.",
    "Referrer-Policy": "Controls how much referrer information should be included with requests.",
    "Permissions-Policy": "Controls which browser features can be used by the site.",
}

class SecurityHeaderAnalyzer:
    def __init__(self, threshold=0.8):
        self.threshold = threshold

    async def analyze_security_headers_async(self, url, session):
        try:
            async with session.get(url) as response:
                headers = response.headers
                used_headers = {}
                missing_headers = {}

                for header, description in SECURITY_HEADERS.items():
                    if header in headers:
                        used_headers[header] = description
                    else:
                        missing_headers[header] = description

                return used_headers, missing_headers

        except aiohttp.ClientError as e:
            print(f"Error analyzing {url}: {e}")
            return {}, {}

    async def process_url_async(self, url, session, output_file=None):
        parsed_url = urlparse(url)
        if not parsed_url.scheme:
            url = "https://" + url

        try:
            used_headers, missing_headers = await self.analyze_security_headers_async(url, session)

            with open(output_file, 'a') as f:
                f.write(f"\nDomain: {url}\n\n")
                f.write("\nUsed security headers:\n")
                self.write_headers_to_file(used_headers, "green", f)

                f.write("\nMissing security headers:\n")
                self.write_headers_to_file(missing_headers, "red", f)

                grade = self.get_grade(used_headers)
                f.write(f"\n\nThe Grade of website is : {grade}\n")
                f.write("---------------------------------------------\n")

        except Exception as e:
            print(f"Error processing {url}: {e}")

    def write_headers_to_file(self, headers, color, file_obj):
        for header, description in headers.items():
            file_obj.write(f"{colored(header, color)}: {description}\n")

    def get_grade(self, used_headers):
        num_headers = len(SECURITY_HEADERS)
        num_used_headers = len(used_headers)

        if num_used_headers == num_headers:
            return "A+"
        elif num_used_headers >= num_headers * self.threshold:
            return "A"
        elif num_used_headers >= num_headers * 0.8:
            return "B"
        elif num_used_headers >= num_headers * 0.7:
            return "C"
        elif num_used_headers >= num_headers * 0.6:
            return "D"
        else:
            return "F"

async def analyze_urls_async(urls, output_file=None, threshold=0.8):
    async with aiohttp.ClientSession() as session:
        analyzer = SecurityHeaderAnalyzer(threshold)
        tasks = [analyzer.process_url_async(url.strip(), session, output_file) for url in urls]
        await asyncio.gather(*tasks)

def analyze_urls_from_file(file_path, output_file=None, threshold=0.8):
    with open(file_path) as file:
        urls = [line.strip() for line in file]
    asyncio.run(analyze_urls_async(urls, output_file, threshold))

def analyze_urls_from_input(url, output_file=None, threshold=0.8):
    urls = [url]
    asyncio.run(analyze_urls_async(urls, output_file, threshold))

# Example usage:
# analyze_urls_from_input("https://example.com", "output.txt", 0.8)

