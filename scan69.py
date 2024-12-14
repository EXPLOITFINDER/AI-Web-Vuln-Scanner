import asyncio
import aiohttp
import urllib.parse
from bs4 import BeautifulSoup
import argparse
from termcolor import colored
import random
import string
import os
import re
import time
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
import json
from datetime import datetime
import logging
from logging.handlers import RotatingFileHandler
import openai
from dotenv import load_dotenv
from tqdm import tqdm
import base64

# Carica le variabili d'ambiente dal file .env
load_dotenv()

# Configura la chiave API di OpenAI
openai.api_key = os.getenv("OPENAI_API_KEY")

# Verifica che la chiave API sia stata caricata
if not openai.api_key:
    print(colored("[ERROR] La chiave API di OpenAI non è impostata. Imposta la variabile d'ambiente OPENAI_API_KEY.", 'red'))
    exit(1)
else:
    print(colored("[INFO] Chiave API di OpenAI caricata correttamente.", 'green'))

# Configura logging avanzato con rotazione
handler = RotatingFileHandler("vulnerability_scanner.log", maxBytes=5*1024*1024, backupCount=2, encoding='utf-8')  # 5 MB per file, 2 backup
logging.basicConfig(
    handlers=[handler],
    level=logging.DEBUG,  # Imposta su DEBUG per ottenere più dettagli durante il testing
    format='%(asctime)s - %(levelname)s - %(message)s'
)

# Lista di User-Agent comuni
USER_AGENTS = [
    # Lista di vari User-Agent per la randomizzazione
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko)\
     Chrome/91.0.4472.124 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko)\
     Version/14.0.3 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko)\
     Chrome/91.0.4472.114 Safari/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 14_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko)\
     Version/14.0 Mobile/15E148 Safari/604.1",
    # Aggiungi altri User-Agent se necessario
]

# Funzione per ottenere un User-Agent casuale
def get_random_user_agent():
    return random.choice(USER_AGENTS)

# Funzione per interagire con OpenAI GPT-3.5-turbo
async def interact_with_openai(prompt):
    try:
        response = await openai.ChatCompletion.acreate(
            model="gpt-3.5-turbo",
            messages=[
                {"role": "system", "content": "Sei un esperto di sicurezza informatica che verifica e descrive vulnerabilità secondo gli standard OWASP Top 10."},
                {"role": "user", "content": prompt}
            ],
            max_tokens=800,
            n=1,
            stop=None,
            temperature=0.5,
        )
        return response.choices[0].message['content'].strip()
    except Exception as e:
        logging.error(f"Errore nella comunicazione con OpenAI: {e}")
        return "Errore nella generazione della risposta da OpenAI."

# Crawler Selenium per raccogliere informazioni su link e form, gestendo i contenuti dinamici
def selenium_crawl(base_url, max_depth=3):
    print(f"[INFO] Crawling target con Selenium: {base_url}")
    logging.info(f"Crawling target con Selenium: {base_url}")
    options = Options()
    options.add_argument('--headless')
    options.add_argument('--no-sandbox')
    options.add_argument('--disable-dev-shm-usage')
    options.add_argument(f'user-agent={get_random_user_agent()}')

    try:
        driver = webdriver.Chrome(options=options)
    except Exception as e:
        logging.error(f"Errore nell'avvio di Chrome WebDriver: {e}")
        print(colored(f"[ERROR] Errore nell'avvio di Chrome WebDriver: {e}", 'red'))
        exit(1)

    visited = set()
    to_visit = [(base_url, 0)]
    found_forms = []
    found_actions = []

    while to_visit:
        current_url, depth = to_visit.pop(0)
        if current_url in visited or depth > max_depth:
            continue

        visited.add(current_url)
        print(f"[INFO] Visiting: {current_url} at depth {depth}")
        logging.info(f"Visiting: {current_url} at depth {depth}")
        try:
            driver.get(current_url)
        except Exception as e:
            logging.error(f"Errore nell'apertura di {current_url}: {e}")
            continue

        try:
            wait = WebDriverWait(driver, 10)  # Tempo di attesa aumentato
            # Attendi che il body sia presente
            wait.until(EC.presence_of_element_located((By.TAG_NAME, "body")))
        except Exception as e:
            logging.warning(f"Timeout while waiting for body to load at {current_url}: {e}")
            continue

        # Scroll della pagina per caricare il contenuto dinamico
        try:
            last_height = driver.execute_script("return document.body.scrollHeight")
        except Exception as e:
            logging.error(f"Errore nell'esecuzione dello script per scrollHeight a {current_url}: {e}")
            continue

        while True:
            try:
                driver.execute_script("window.scrollTo(0, document.body.scrollHeight);")
                time.sleep(1)  # Tempo di attesa aumentato per consentire il caricamento
                new_height = driver.execute_script("return document.body.scrollHeight")
                if new_height == last_height:
                    break
                last_height = new_height
            except Exception as e:
                logging.error(f"Errore durante lo scrolling della pagina {current_url}: {e}")
                break

        try:
            # Attendi che tutti i form siano presenti
            wait.until(EC.presence_of_all_elements_located((By.TAG_NAME, "form")))
        except Exception as e:
            logging.warning(f"Timeout while waiting for forms to load at {current_url}: {e}")

        try:
            # Attendi che tutti i link siano presenti
            wait.until(EC.presence_of_all_elements_located((By.TAG_NAME, "a")))
        except Exception as e:
            logging.warning(f"Timeout while waiting for links to load at {current_url}: {e}")

        html_content = driver.page_source
        soup = BeautifulSoup(html_content, "html.parser")

        # Trova tutti i form
        for form in soup.find_all("form"):
            form_action = form.get("action")
            if not form_action:
                logging.warning(f"Form senza action trovato a {current_url}. Impostato action al current_url.")
                form_action = current_url
            form_details = {
                "action": urllib.parse.urljoin(current_url, form_action),
                "method": form.get("method", "get").lower(),
                "inputs": []
            }
            for input_tag in form.find_all(["input", "textarea", "select"]):
                input_name = input_tag.get("name")
                input_type = input_tag.get("type", "text")
                if input_name:
                    form_details["inputs"].append({
                        "name": input_name,
                        "type": input_type,
                        "value": input_tag.get("value", "")
                    })
            found_forms.append(form_details)
            logging.info(f"Trovato form: {form_details}")
            # Aggiungi l'action URL del form alla lista found_actions se non già presente
            action_url = form_details["action"]
            if action_url not in found_actions:
                found_actions.append(action_url)
                logging.info(f"Aggiunto action URL dal form: {action_url}")
                if action_url not in visited:
                    to_visit.append((action_url, depth + 1))

        # Trova tutti gli endpoint action da form, link e script
        for tag in soup.find_all(['a', 'form', 'script'], href=True):
            action_url = urllib.parse.urljoin(current_url, tag.get('href', ''))
            parsed_base = urllib.parse.urlparse(base_url)
            parsed_action = urllib.parse.urlparse(action_url)
            base_netloc = parsed_base.netloc
            action_netloc = parsed_action.netloc

            # Gestione corretta delle netloc per includere subdirectory
            if base_netloc == action_netloc and action_url not in found_actions:
                found_actions.append(action_url)
                if action_url not in visited:
                    to_visit.append((action_url, depth + 1))
                logging.info(f"Trovato action URL: {action_url}")

        # Trova tutti i link per il crawling
        for link in soup.find_all("a", href=True):
            full_url = urllib.parse.urljoin(current_url, link["href"])
            parsed_base = urllib.parse.urlparse(base_url)
            parsed_full = urllib.parse.urlparse(full_url)
            base_netloc = parsed_base.netloc
            full_netloc = parsed_full.netloc

            if base_netloc == full_netloc and full_url not in found_actions:
                found_actions.append(full_url)
                if full_url not in visited:
                    to_visit.append((full_url, depth + 1))
                logging.info(f"Trovato link per il crawling: {full_url}")

    driver.quit()
    print(f"\n[INFO] Trovati {len(found_forms)} forms e {len(found_actions)} action URLs.")
    logging.info(f"Trovati {len(found_forms)} forms e {len(found_actions)} action URLs.")
    return found_forms, found_actions

# Genera payload avanzati da file txt nella directory specificata e applica evasive
def generate_payloads_from_directory(directory):
    payloads = []

    # Controlla se la directory esiste
    if not os.path.isdir(directory):
        print(f"[ERROR] La directory {directory} non esiste.")
        logging.error(f"La directory {directory} non esiste.")
        return payloads

    print(f"[INFO] Caricamento dei payload dalla directory: {directory}")
    logging.info(f"Caricamento dei payload dalla directory: {directory}")
    for root, _, files in os.walk(directory):
        for file in files:
            if file.endswith(".txt"):
                filepath = os.path.join(root, file)
                print(f"[INFO] Lettura del file di payload: {filepath}")
                logging.info(f"Lettura del file di payload: {filepath}")
                try:
                    with open(filepath, 'r', encoding='utf-8', errors='replace') as f:
                        for line in f:
                            payload = line.strip()
                            if payload:
                                # Aggiungi varianti evasive del payload
                                payloads.extend([
                                    payload,
                                    urllib.parse.quote(payload),  # URL encoding
                                    payload.replace("<", "&lt;").replace(">", "&gt;"),  # HTML entities
                                    payload.replace("script", "scr<script>ipt"),  # Tag splitting
                                    ''.join(f"\\u{ord(c):04x}" for c in payload),  # Codifica Unicode con doppio backslash
                                    base64.b64encode(payload.encode()).decode(),  # Base64 encoding
                                    urllib.parse.quote(base64.b64encode(payload.encode()).decode())  # Double URL encoding
                                ])
                except Exception as e:
                    print(f"[ERROR] Errore durante la lettura del file {filepath}: {e}")
                    logging.error(f"Errore durante la lettura del file {filepath}: {e}")
    unique_payloads = list(set(payloads))  # Rimuovi duplicati
    print(f"[INFO] Totale payload caricati: {len(unique_payloads)}")
    logging.info(f"Totale payload caricati: {len(unique_payloads)}")
    return unique_payloads

# Genera payload dinamici adattivi basati sulla risposta del server
def generate_dynamic_payloads(base_payload, server_response):
    dynamic_payloads = [base_payload]
    if "waf" in server_response.lower():
        # Scegli in modo casuale tra diverse tecniche di bypass
        bypass_methods = [
            lambda p: p.replace("<", "\\u003C"),
            lambda p: p.replace("alert", "a\\u006Cert"),
            lambda p: base64.b64encode(p.encode()).decode(),
            lambda p: urllib.parse.quote(base64.b64encode(p.encode()).decode()),
            lambda p: p[::-1],  # Reverse string
            lambda p: ''.join(random.choice([c, f"\\x{ord(c):02x}"]) for c in p)  # Random hex encoding
        ]
        selected_methods = random.sample(bypass_methods, k=random.randint(1, len(bypass_methods)))
        for method in selected_methods:
            try:
                dynamic_payload = method(base_payload)
                dynamic_payloads.append(dynamic_payload)
            except Exception as e:
                logging.error(f"Errore nella generazione del payload dinamico: {e}")
    return dynamic_payloads

# Analizza la risposta del server e stampa eventuali vulnerabilità rilevate
def analyze_response(response, payload, unique_vulnerabilities, processed_payloads, url, baseline_response_text, attack_response_text):
    if attack_response_text is None:
        attack_response_text = response.text
    if baseline_response_text is None:
        baseline_response_text = ""

    decoded_attack_response = urllib.parse.unquote(attack_response_text)
    decoded_baseline_response = urllib.parse.unquote(baseline_response_text)

    vulnerabilities_detected = []

    # Confronto dei tempi di risposta
    baseline_time = response.elapsed.total_seconds() if hasattr(response, 'elapsed') else 0
    attack_time = response.elapsed.total_seconds() if hasattr(response, 'elapsed') else 0
    time_difference = attack_time - baseline_time

    # Definisci una soglia per considerare un ritardo significativo
    time_threshold = 2  # secondi

    # Controllo XSS con contesto
    if payload in decoded_attack_response:
        # Verifica se il payload è all'interno di uno script
        xss_pattern = re.compile(rf'<script.*?>.*{re.escape(payload)}.*?</script>', re.IGNORECASE)
        if xss_pattern.search(decoded_attack_response):
            vuln_type = "A7: Reflected XSS"
            if vuln_type not in unique_vulnerabilities:
                vulnerabilities_detected.append(vuln_type)
                logging.info(f"[VULNERABLE - REFLECTED XSS] URI: {url}, Payload: {payload}, Reason: Payload was reflected within a script tag.")
                print(colored(f"[VULNERABLE - Reflected XSS] URI: {url}\nFIELD: {payload}\nREASON: The payload was successfully reflected within a script tag in the response, indicating a cross-site scripting vulnerability.\n", 'red', attrs=['bold']))
                asyncio.create_task(verify_and_describe_vulnerability("Reflected XSS", url, payload, attack_response_text))
                print('=' * 50)

    # Controllo SQL Injection basato su differenze nella risposta
    if re.search(r"(?i)(sql syntax|mysql_fetch|unclosed quotation mark|you have an error in your sql syntax|native client|sql server|syntax error|ORA-)", decoded_attack_response):
        vuln_type = "A3: SQL Injection"
        if vuln_type not in unique_vulnerabilities:
            vulnerabilities_detected.append(vuln_type)
            logging.info(f"[VULNERABLE - SQL INJECTION] URI: {url}, Payload: {payload}, Reason: SQL error message detected in response.")
            print(colored(f"[VULNERABLE - SQL INJECTION] URI: {url}\nFIELD: {payload}\nREASON: SQL error message detected in the response, suggesting that the input was improperly handled by the database.\n", 'red', attrs=['bold']))
            asyncio.create_task(verify_and_describe_vulnerability("SQL Injection", url, payload, attack_response_text))
            print('=' * 50)

    # Controllo RCE basato su ritardo nella risposta
    if any(keyword in payload.lower() for keyword in ["; sleep", "&& sleep", "| timeout", "waitfor delay"]):
        if time_difference > time_threshold:
            vuln_type = "A10: Remote Command Execution"
            if vuln_type not in unique_vulnerabilities:
                vulnerabilities_detected.append(vuln_type)
                logging.info(f"[VULNERABLE - RCE] Remote Command Execution rilevata a {url}, Payload: {payload}, Reason: Ritardo significativo nella risposta.")
                print(colored(f"[VULNERABLE - RCE] Remote Command Execution rilevata.\nURI: {url}\nREASON: Il ritardo nella risposta è significativo, indicando che il payload ha eseguito un comando sul server.\n", 'red', attrs=['bold']))
                asyncio.create_task(verify_and_describe_vulnerability("Remote Command Execution", url, payload, attack_response_text))
                print('=' * 50)

    # Controllo SSRF con analisi logica della risposta
    ssrf_patterns = [
        r"localhost", r"169\.254\.169\.254", r"internal", r"metadata\.google\.internal", r"127\.0\.0\.1"
    ]
    if any(re.search(pattern, decoded_attack_response, re.IGNORECASE) for pattern in ssrf_patterns):
        # Verifica la presenza di indicazioni di accesso a risorse interne
        if re.search(r"(?i)(HTTP|200 OK)", decoded_attack_response):
            vuln_type = "A10: Server-Side Request Forgery"
            if vuln_type not in unique_vulnerabilities:
                vulnerabilities_detected.append(vuln_type)
                logging.info(f"[VULNERABLE - SSRF] Server-Side Request Forgery rilevata a {url}, Payload: {payload}, Reason: Risposta suggerisce una richiesta a risorse interne.")
                print(colored(f"[VULNERABLE - SSRF] Server-Side Request Forgery rilevata.\nURI: {url}\nREASON: Il payload ha innescato una risposta che indica l'accesso a risorse interne, suggerendo una vulnerabilità di server-side request forgery.\n", 'red', attrs=['bold']))
                asyncio.create_task(verify_and_describe_vulnerability("Server-Side Request Forgery", url, payload, attack_response_text))
                print('=' * 50)

    # Controllo Path Traversal
    path_traversal_patterns = [
        r"root:x:0:0", r"boot\.ini", r"etc/passwd", r"windows\\win\.ini", r"config\.php", r"wp-config\.php"
    ]
    if any(re.search(pattern, decoded_attack_response, re.IGNORECASE) for pattern in path_traversal_patterns):
        # Verifica che il contenuto sia sensibile e non solo un riflesso del payload
        if any(keyword in decoded_attack_response for keyword in ["root:x", "boot.ini", "etc/passwd", "wp-config.php"]):
            vuln_type = "A5: Path Traversal"
            if vuln_type not in unique_vulnerabilities:
                vulnerabilities_detected.append(vuln_type)
                logging.info(f"[VULNERABLE - PATH TRAVERSAL] URI: {url}, Payload: {payload}, Reason: Percorso di file sensibile rilevato nella risposta.")
                print(colored(f"[VULNERABLE - PATH TRAVERSAL] URI: {url}\nFIELD: {payload}\nREASON: La risposta contiene percorsi di file sensibili, indicando una vulnerabilità di path traversal.\n", 'red', attrs=['bold']))
                asyncio.create_task(verify_and_describe_vulnerability("Path Traversal", url, payload, attack_response_text))
                print('=' * 50)

    # Controllo Command Injection
    command_injection_patterns = [
        r"command not found", r"sh: ", r"syntax error near unexpected token", r"is not recognized as an internal or external command",
        r"permission denied", r"Operation timed out", r"Invalid argument", r"unknown command"
    ]
    if any(re.search(pattern, decoded_attack_response, re.IGNORECASE) for pattern in command_injection_patterns):
        vuln_type = "A3: Command Injection"
        if vuln_type not in unique_vulnerabilities:
            vulnerabilities_detected.append(vuln_type)
            logging.info(f"[VULNERABLE - COMMAND INJECTION] URI: {url}, Payload: {payload}, Reason: Errore di command injection rilevato nella risposta.")
            print(colored(f"[VULNERABLE - COMMAND INJECTION] URI: {url}\nFIELD: {payload}\nREASON: La risposta contiene un errore di comando, suggerendo una command injection riuscita.\n", 'red', attrs=['bold']))
            asyncio.create_task(verify_and_describe_vulnerability("Command Injection", url, payload, attack_response_text))
            print('=' * 50)

    # Controllo File Inclusion
    file_inclusion_patterns = [
        r"failed to open stream", r"No such file or directory", r"inclusion failure", r"include\(\)", r"require_once"
    ]
    if any(re.search(pattern, decoded_attack_response, re.IGNORECASE) for pattern in file_inclusion_patterns):
        vuln_type = "A6: File Inclusion"
        if vuln_type not in unique_vulnerabilities:
            vulnerabilities_detected.append(vuln_type)
            logging.info(f"[VULNERABLE - FILE INCLUSION] URI: {url}, Payload: {payload}, Reason: Errore di inclusione di file rilevato nella risposta.")
            print(colored(f"[VULNERABLE - FILE INCLUSION] URI: {url}\nFIELD: {payload}\nREASON: La risposta indica un errore di inclusione, suggerendo una vulnerabilità di file inclusion.\n", 'red', attrs=['bold']))
            asyncio.create_task(verify_and_describe_vulnerability("File Inclusion", url, payload, attack_response_text))
            print('=' * 50)

    # Analisi avanzata dei tempi di risposta
    if time_difference > time_threshold:
        vuln_type = "A10: Remote Command Execution"
        if vuln_type not in unique_vulnerabilities:
            vulnerabilities_detected.append(vuln_type)
            logging.info(f"[VULNERABLE - RCE] Remote Command Execution rilevata a {url}, Payload: {payload}, Reason: Ritardo significativo nella risposta.")
            print(colored(f"[VULNERABLE - RCE] Remote Command Execution rilevata.\nURI: {url}\nREASON: Il ritardo nella risposta è significativo, indicando che il payload ha eseguito un comando sul server.\n", 'red', attrs=['bold']))
            asyncio.create_task(verify_and_describe_vulnerability("Remote Command Execution", url, payload, attack_response_text))
            print('=' * 50)

    for vuln in vulnerabilities_detected:
        unique_vulnerabilities.add(vuln)

# Funzione per verificare e descrivere la vulnerabilità con OpenAI
async def verify_and_describe_vulnerability(vuln_type, url, payload, response_text):
    # Costruisci il prompt per la verifica
    verification_prompt = (
        f"Il seguente payload '{payload}' è stato utilizzato sull'URL '{url}'. "
        f"La risposta del server contiene indicatori di una vulnerabilità di tipo '{vuln_type}'. "
        f"Valuta se la vulnerabilità è confermata sulla base della risposta fornita.\n"
        f"Risposta del server:\n{response_text}\n"
        f"Rispondi solo con 'Confermato' o 'Non Confermato'."
    )
    verification_response = await interact_with_openai(verification_prompt)

    if "Confermato" in verification_response:
        # Descrivi la vulnerabilità
        description_prompt = (
            f"Descrivi dettagliatamente la vulnerabilità di tipo '{vuln_type}' rilevata sull'URL '{url}' utilizzando il payload '{payload}'. "
            f"Includi una spiegazione tecnica, il punteggio di gravità secondo OWASP Top 10 e suggerimenti per la mitigazione."
        )
        description = await interact_with_openai(description_prompt)

        # Genera un Proof of Concept (PoC)
        poc_prompt = (
            f"Genera un Proof of Concept (PoC) per dimostrare la vulnerabilità di tipo '{vuln_type}' rilevata sull'URL '{url}' con il payload '{payload}'. "
            f"Il PoC dovrebbe includere passaggi chiari e, se applicabile, codice di esempio."
        )
        poc = await interact_with_openai(poc_prompt)

        # Stampa e logga le informazioni
        print(colored(f"DESCRIZIONE VULNERABILITÀ: {description}\nPOC: {poc}\n", 'magenta', attrs=['bold']))
        logging.info(f"Descrizione: {description}")
        logging.info(f"PoC: {poc}")
    else:
        logging.info(f"Vulnerabilità '{vuln_type}' su {url} con payload '{payload}' non confermata da OpenAI.")
        print(colored(f"[INFO] Vulnerabilità '{vuln_type}' su {url} con payload '{payload}' non confermata.", 'cyan'))

# Analizza gli header HTTP per identificare versioni software obsolete o configurazioni errate
def analyze_headers(headers, url, unique_vulnerabilities, payload):
    server_header = headers.get('Server', '')
    if server_header:
        obsolete_servers = ["Apache/2.2", "nginx/1.14", "Microsoft-IIS/7.5"]
        for obsolete in obsolete_servers:
            if obsolete in server_header:
                vuln_type = "A5: Security Misconfiguration"
                if vuln_type not in unique_vulnerabilities:
                    logging.info(f"[VULNERABLE - Security Misconfiguration] URI: {url}, Server Header: {server_header}, Reason: Server software obsolete ({obsolete}).")
                    print(colored(f"[VULNERABLE - Security Misconfiguration] URI: {url}\nHEADER: Server\nREASON: Server software obsolete ({obsolete}), indicando potenziale security misconfiguration.\n", 'red', attrs=['bold']))
                    unique_vulnerabilities.add(vuln_type)
                    print('=' * 50)

    x_powered_by = headers.get('X-Powered-By', '')
    if x_powered_by:
        vuln_type = "A5: Security Misconfiguration"
        if vuln_type not in unique_vulnerabilities:
            logging.info(f"[VULNERABLE - Security Misconfiguration] URI: {url}, X-Powered-By Header: {x_powered_by}, Reason: Revealing internal technologies.")
            print(colored(f"[VULNERABLE - Security Misconfiguration] URI: {url}\nHEADER: X-Powered-By\nREASON: Revealing internal technologies ({x_powered_by}), indicando potenziale security misconfiguration.\n", 'red', attrs=['bold']))
            unique_vulnerabilities.add(vuln_type)
            print('=' * 50)

# Testa un form inviando il payload e analizzando la risposta
async def test_form(session, form_url, method, inputs, payload, unique_vulnerabilities, processed_payloads, semaphore):
    async with semaphore:
        try:
            # Verifica se il payload è già stato elaborato per evitare duplicati
            if (form_url, payload) in processed_payloads:
                return
            processed_payloads.add((form_url, payload))

            # Crea dati del form con il payload in tutti i campi testabili
            data = {}
            for field in inputs:
                input_name = field["name"]
                if field["type"] in ["text", "textarea", "email", "url", "search", "tel"]:
                    data[input_name] = payload
                elif field["type"] == "checkbox":
                    data[input_name] = "on"
                elif field["type"] == "radio":
                    data[input_name] = field.get("value", "on")
                elif field["type"] == "select-one":
                    data[input_name] = field.get("value", "")
                else:
                    data[input_name] = field.get("value", "")

            # Randomizza il User-Agent per ogni richiesta
            headers = {
                "User-Agent": get_random_user_agent()
            }

            # Debug: Log dettagli sulla richiesta
            logging.debug(f"Invio payload al form URL: {form_url}")
            logging.debug(f"Metodo: {method.upper()}")
            logging.debug(f"Campi inviati: {data}")
            logging.info(f"Invio payload '{payload}' al form URL: {form_url} con metodo {method.upper()} nei campi {list(data.keys())}")

            # Invia il payload di attacco e misura il tempo di risposta
            if method == "post":
                async with session.post(form_url, data=data, headers=headers, timeout=10) as attack_response:
                    attack_response_text = await attack_response.text()
                    attack_time = attack_response.elapsed.total_seconds() if hasattr(attack_response, 'elapsed') else 0

                    # Debug: Log della risposta
                    logging.debug(f"Risposta ricevuta da {form_url}: Status {attack_response.status}, Tempo {attack_time}s")
                    logging.info(f"Payload '{payload}' inviato a {form_url} con metodo {method.upper()} nei campi {list(data.keys())}. Risposta status: {attack_response.status}, Tempo risposta: {attack_time}s")

                    analyze_response(
                        response=attack_response,
                        payload=payload,
                        unique_vulnerabilities=unique_vulnerabilities,
                        processed_payloads=processed_payloads,
                        url=form_url,
                        baseline_response_text=None,
                        attack_response_text=attack_response_text
                    )
            else:
                async with session.get(form_url, params=data, headers=headers, timeout=10) as attack_response:
                    attack_response_text = await attack_response.text()
                    attack_time = attack_response.elapsed.total_seconds() if hasattr(attack_response, 'elapsed') else 0

                    # Debug: Log della risposta
                    logging.debug(f"Risposta ricevuta da {form_url}: Status {attack_response.status}, Tempo {attack_time}s")
                    logging.info(f"Payload '{payload}' inviato a {form_url} con metodo {method.upper()} nei campi {list(data.keys())}. Risposta status: {attack_response.status}, Tempo risposta: {attack_time}s")

                    analyze_response(
                        response=attack_response,
                        payload=payload,
                        unique_vulnerabilities=unique_vulnerabilities,
                        processed_payloads=processed_payloads,
                        url=form_url,
                        baseline_response_text=None,
                        attack_response_text=attack_response_text
                    )

                logging.debug(f"Payload '{payload}' inviato a {form_url} con metodo {method.upper()} nei campi {list(data.keys())}")
        except aiohttp.ClientError as e:
            logging.error(f"Error testing form at {form_url}: {e}")
        except Exception as e:
            logging.error(f"Unexpected error testing form at {form_url}: {e}")

# Testa i parametri GET in URL inviando il payload e analizzando la risposta
async def test_get_params(session, url, params, payload, unique_vulnerabilities, processed_payloads, semaphore):
    async with semaphore:
        try:
            if not params:
                return

            data = {param: payload for param in params}
            headers = {
                "User-Agent": get_random_user_agent()
            }
            logging.info(f"Invio payload nei parametri GET di {url}: {data}")
            logging.debug(f"GET request to {url} with params: {data}")
            async with session.get(url, params=data, headers=headers, timeout=10) as response:
                attack_response_text = await response.text()
                attack_time = response.elapsed.total_seconds() if hasattr(response, 'elapsed') else 0

                # Debug: Log della risposta
                logging.debug(f"Risposta ricevuta da {url}: Status {response.status}, Tempo {attack_time}s")
                logging.info(f"Payload '{payload}' inviato al parametro '{params}' su URL: {url}. Risposta status: {response.status}, Tempo risposta: {attack_time}s")

                analyze_response(
                    response=response,
                    payload=payload,
                    unique_vulnerabilities=unique_vulnerabilities,
                    processed_payloads=processed_payloads,
                    url=url,
                    baseline_response_text=None,
                    attack_response_text=attack_response_text
                )
        except aiohttp.ClientError as e:
            logging.error(f"Error testing GET parameters at {url}: {e}")
        except Exception as e:
            logging.error(f"Unexpected error testing GET parameters at {url}: {e}")

# Testa i parametri POST in URL inviando il payload e analizzando la risposta
async def test_post_params(session, url, params, payload, unique_vulnerabilities, processed_payloads, semaphore):
    async with semaphore:
        try:
            if (url, payload) in processed_payloads:
                return
            processed_payloads.add((url, payload))

            if not params:
                # Se non ci sono parametri, invia il payload nel corpo della richiesta
                data = payload
            else:
                data = {param: payload for param in params}
            headers = {
                "User-Agent": get_random_user_agent()
            }
            logging.info(f"Invio payload nei parametri POST di {url}: {data}")
            logging.debug(f"POST request to {url} with data: {data}")
            async with session.post(url, data=data, headers=headers, timeout=10) as response:
                attack_response_text = await response.text()
                attack_time = response.elapsed.total_seconds() if hasattr(response, 'elapsed') else 0

                # Debug: Log della risposta
                logging.debug(f"Risposta ricevuta da {url}: Status {response.status}, Tempo {attack_time}s")
                logging.info(f"Payload '{payload}' inviato al parametro '{params}' su URL: {url}. Risposta status: {response.status}, Tempo risposta: {attack_time}s")

                analyze_response(
                    response=response,
                    payload=payload,
                    unique_vulnerabilities=unique_vulnerabilities,
                    processed_payloads=processed_payloads,
                    url=url,
                    baseline_response_text=None,
                    attack_response_text=attack_response_text
                )
        except aiohttp.ClientError as e:
            logging.error(f"Error testing POST parameters at {url}: {e}")
        except Exception as e:
            logging.error(f"Unexpected error testing POST parameters at {url}: {e}")

# Testa gli header HTTP inviando i payload e analizzando la risposta
async def test_headers(session, url, payloads, processed_payloads, unique_vulnerabilities, semaphore):
    async with semaphore:
        if len(payloads) < 3:
            logging.error(f"Non ci sono abbastanza payload per testare gli headers a {url}. Necessari: 3, Trovati: {len(payloads)}")
            print(f"[ERROR] Non ci sono abbastanza payload per testare gli headers a {url}. Necessari: 3, Trovati: {len(payloads)}")
            return

        # Prepara i payload per gli headers
        user_agent_payload = payloads[0]
        referer_payload = payloads[1]
        cookie_payload = payloads[2]

        # Randomizza il User-Agent per ogni richiesta
        headers = {
            "User-Agent": get_random_user_agent(),
            "Referer": referer_payload,
            "Cookie": f"session={cookie_payload}"
        }
        try:
            # Debug: Log dettagli sulla richiesta Headers
            logging.debug(f"Test Headers su {url} con Referer: {referer_payload}, Cookie: {cookie_payload}")
            logging.info(f"Invio payload negli headers su {url}. Referer: '{referer_payload}', Cookie: '{cookie_payload}'")

            # Invia la richiesta con i payload negli headers e misura il tempo di risposta
            async with session.get(url, headers=headers, timeout=10) as attack_response:
                attack_response_text = await attack_response.text()
                attack_time = attack_response.elapsed.total_seconds() if hasattr(attack_response, 'elapsed') else 0

                # Debug: Log della risposta
                logging.debug(f"Risposta ricevuta da {url}: Status {attack_response.status}, Tempo {attack_time}s")
            analyze_response(
                response=attack_response,
                payload=cookie_payload,
                unique_vulnerabilities=unique_vulnerabilities,
                processed_payloads=processed_payloads,
                url=url,
                baseline_response_text=None,
                attack_response_text=attack_response_text
            )
        except aiohttp.ClientError as e:
            logging.error(f"Header test failed at {url}: {e}")
            print(f"[ERROR] Header test failed at {url}: {e}")
        except Exception as e:
            logging.error(f"Unexpected error during header testing at {url}: {e}")

# Genera un report dettagliato delle vulnerabilità trovate
def generate_report(vulnerabilities):
    report = {
        "timestamp": datetime.now().isoformat(),
        "vulnerabilities": []
    }

    vulnerability_messages = {
        "A1: Broken Access Control": "Broken Access Control",
        "A2: Cryptographic Failures": "Cryptographic Failures",
        "A3: Injection": "Injection",
        "A3: Command Injection": "Command Injection",
        "A5: Security Misconfiguration": "Security Misconfiguration",
        "A5: Path Traversal": "Path Traversal",
        "A6: Vulnerable and Outdated Components": "Vulnerable and Outdated Components",
        "A6: File Inclusion": "File Inclusion",
        "A7: Identification and Authentication Failures": "Identification and Authentication Failures",
        "A7: Reflected XSS": "Reflected Cross-Site Scripting (XSS)",
        "A8: Software and Data Integrity Failures": "Software and Data Integrity Failures",
        "A9: Security Logging and Monitoring Failures": "Security Logging and Monitoring Failures",
        "A10: Server-Side Request Forgery": "Server-Side Request Forgery (SSRF)",
        "A10: Remote Command Execution": "Remote Command Execution",
        "A6: Potential Length Difference": "Potential Length Difference"
    }

    for vuln in vulnerabilities:
        vuln_type = vulnerability_messages.get(vuln, vuln)
        score = get_owasp_score(vuln_type)
        report["vulnerabilities"].append({
            "type": vuln_type,
            "owasp_score": score
        })

    # Salva il report in formato JSON
    try:
        with open("vulnerability_report.json", "w", encoding='utf-8') as f:
            json.dump(report, f, indent=4)
        logging.info("Report JSON generato correttamente.")
    except Exception as e:
        logging.error(f"Errore nella scrittura del report JSON: {e}")
        print(f"[ERROR] Errore nella scrittura del report JSON: {e}")

    # Salva il report in formato HTML (semplice)
    try:
        with open("vulnerability_report.html", "w", encoding='utf-8') as f:
            f.write("<html><head><title>Vulnerability Report</title></head><body>")
            f.write(f"<h1>Vulnerability Report - {report['timestamp']}</h1>")
            f.write("<ul>")
            for vuln in report["vulnerabilities"]:
                f.write(f"<li><strong>{vuln['type']}</strong> - OWASP Score: {vuln['owasp_score']}</li>")
            f.write("</ul>")
            f.write("</body></html>")
        logging.info("Report HTML generato correttamente.")
    except Exception as e:
        logging.error(f"Errore nella scrittura del report HTML: {e}")
        print(f"[ERROR] Errore nella scrittura del report HTML: {e}")

    print(colored("\n[INFO] Report generato: vulnerability_report.json e vulnerability_report.html", 'green'))

# Assegna uno score basato sull'OWASP Top 10
def get_owasp_score(vuln_type):
    # Implementa uno schema di scoring basato sull'OWASP Top 10
    # Questo è un esempio semplificato
    scoring = {
        "Broken Access Control": 9.8,
        "Cryptographic Failures": 8.9,
        "Injection": 9.9,
        "Command Injection": 9.8,
        "Security Misconfiguration": 7.5,
        "Path Traversal": 7.5,
        "Vulnerable and Outdated Components": 7.0,
        "File Inclusion": 8.5,
        "Identification and Authentication Failures": 9.2,
        "Reflected Cross-Site Scripting (XSS)": 7.4,
        "Software and Data Integrity Failures": 8.1,
        "Security Logging and Monitoring Failures": 6.1,
        "Server-Side Request Forgery (SSRF)": 8.3,
        "Remote Command Execution": 9.8,
        "Potential Length Difference": 5.5
    }
    return scoring.get(vuln_type, 5.0)  # Default score

# Inietta i payload nei form e negli headers trovati
async def start_attack(base_url, forms, actions, payload_directory):
    payloads = generate_payloads_from_directory(payload_directory)
    if not payloads:
        print("[ERROR] Nessun payload trovato. Verifica la directory dei payload.")
        logging.error("[ERROR] Nessun payload trovato. Verifica la directory dei payload.")
        return set()

    # Limitare il numero di payloads per evitare sovraccarichi
    max_payloads = 6000  # Imposta un limite appropriato
    if len(payloads) > max_payloads:
        print(f"[INFO] Riducendo i payloads a {max_payloads} per evitare sovraccarichi.")
        payloads = payloads[:max_payloads]

    unique_vulnerabilities = set()
    processed_payloads = set()

    connector = aiohttp.TCPConnector(limit=20)  # Ridotto il limite di connessioni simultanee
    timeout = aiohttp.ClientTimeout(total=60)  # Impostazione del timeout totale

    # Semaphore per limitare il numero di task concorrenti
    semaphore = asyncio.Semaphore(100)  # Limita a 100 task simultanei

    async with aiohttp.ClientSession(connector=connector, timeout=timeout) as session:
        tasks = []
        total_tasks = 0

        # Prepara le richieste per i form
        for form in forms:
            action = form["action"]
            method = form["method"]
            inputs = form["inputs"]

            form_url = urllib.parse.urljoin(base_url, action)
            parsed_form_url = urllib.parse.urlparse(form_url)
            parsed_base_url = urllib.parse.urlparse(base_url)

            if not parsed_form_url.scheme:
                form_url = parsed_base_url.scheme + "://" + form_url

            if parsed_base_url.netloc != parsed_form_url.netloc:
                continue  # Salta se il dominio è diverso

            for payload in payloads:
                logging.debug(f"Testing payload '{payload}' on form URL: {form_url} with method {method.upper()}")
                task = asyncio.create_task(
                    test_form(session, form_url, method, inputs, payload, unique_vulnerabilities, processed_payloads, semaphore)
                )
                tasks.append(task)
                total_tasks += 1

        # Prepara le richieste per le action URL
        for action_url in actions:
            parsed_action_url = urllib.parse.urlparse(action_url)
            parsed_base_url = urllib.parse.urlparse(base_url)

            if parsed_base_url.netloc != parsed_action_url.netloc:
                continue  # Salta domini diversi

            # Trova i parametri nella URL di azione
            query_params = urllib.parse.parse_qs(parsed_action_url.query)
            params = list(query_params.keys())

            if params:
                # Testa come GET
                for payload in payloads:
                    logging.debug(f"Testing payload '{payload}' on GET parameters of URL: {action_url}")
                    task = asyncio.create_task(
                        test_get_params(session, action_url, params, payload, unique_vulnerabilities, processed_payloads, semaphore)
                    )
                    tasks.append(task)
                    total_tasks += 1

            # Testa l'action URL come endpoint POST
            for payload in payloads:
                logging.debug(f"Testing payload '{payload}' on POST parameters of URL: {action_url}")
                task = asyncio.create_task(
                    test_post_params(session, action_url, params, payload, unique_vulnerabilities, processed_payloads, semaphore)
                )
                tasks.append(task)
                total_tasks += 1

        # Prepara le richieste per testare gli headers
        for action_url in actions:
            logging.debug(f"Testing headers on URL: {action_url}")
            task = asyncio.create_task(test_headers(session, action_url, payloads[:3], processed_payloads, unique_vulnerabilities, semaphore))
            tasks.append(task)
            total_tasks += 1

        # Inizializza la barra di progresso
        progress = tqdm(total=total_tasks, desc="Testing payloads")

        # Passa la barra di progresso ai task
        async def update_progress(task):
            try:
                await task
            finally:
                progress.update(1)

        # Esegui i task con update della barra
        wrapped_tasks = [update_progress(task) for task in tasks]
        results = await asyncio.gather(*wrapped_tasks, return_exceptions=True)
        for result in results:
            if isinstance(result, Exception):
                logging.error(f"Task resulted in exception: {result}")

        progress.close()

    # Genera un report dettagliato
    generate_report(unique_vulnerabilities)
    return unique_vulnerabilities

# Entry point per riga di comando
def main():
    parser = argparse.ArgumentParser(description="Advanced Vulnerability Scanner with Recursive Crawler and OpenAI Integration")
    parser.add_argument("-u", "--url", required=True, help="Target URL")
    parser.add_argument("-d", "--directory", required=True, help="Directory containing payload text files")
    parser.add_argument("-m", "--max_depth", type=int, default=3, help="Maximum depth for crawling")
    args = parser.parse_args()

    # Verifica che il path della directory sia correttamente formattato
    payload_directory = os.path.abspath(args.directory)
    if not os.path.exists(payload_directory):
        print(f"[ERROR] La directory dei payload non esiste: {payload_directory}")
        logging.error(f"La directory dei payload non esiste: {payload_directory}")
        exit(1)

    # Avvia il crawler per trovare tutte le risorse del sito
    forms, actions = selenium_crawl(args.url, args.max_depth)

    # Avvia l'attacco utilizzando i form e gli headers trovati
    unique_vulnerabilities = asyncio.run(start_attack(args.url, forms, actions, payload_directory))

    # Ora, invia una sola richiesta all'API di OpenAI per elaborare la strategia di attacco
    if unique_vulnerabilities:
        vuln_list = "\n".join([f"- {vuln}" for vuln in unique_vulnerabilities])
        strategy_prompt = (
            f"Ho rilevato le seguenti vulnerabilità critiche su '{args.url}':\n{vuln_list}\n\n"
            f"Per favore, fornisci una strategia di attacco dettagliata che sfrutti queste vulnerabilità, includendo tecniche, strumenti e passaggi specifici necessari per eseguire un attacco efficace."
        )
        strategy_response = asyncio.run(interact_with_openai(strategy_prompt))
        logging.info(f"AI Strategy Result: {strategy_response}")
        print(colored(f"\n[AI STRATEGY]\n{strategy_response}", 'blue', attrs=['bold']))
    else:
        print(colored("[INFO] Nessuna vulnerabilità critica rilevata. Nessuna strategia di attacco necessaria.", 'green'))

if __name__ == "__main__":
    main()
