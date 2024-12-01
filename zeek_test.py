import os
import subprocess
import glob
import json
import pandas as pd
import ipaddress
import hashlib
import shutil
from datetime import datetime

class ZeekAnalyzer:
    def __init__(self, pcap_file, zeek_path='zeek', output_dir='zeek_logs', secure_dir='secure_evidence', local_nets=None, duration_threshold=10.0, bytes_threshold=1000):
        self.pcap_file = pcap_file
        self.zeek_path = zeek_path
        self.output_dir = output_dir
        self.secure_dir = secure_dir
        self.logs = {}
        self.local_nets = local_nets or ['192.168.1.0/24']
        self.duration_threshold = duration_threshold
        self.bytes_threshold = bytes_threshold

    def run_zeek(self):
        """Uruchamia Zeeka na pliku PCAP z użyciem zeek_config.zeek."""
        if not os.path.exists(self.output_dir):
            os.makedirs(self.output_dir)

        pcap_full_path = os.path.abspath(self.pcap_file)
        zeek_config_path = os.path.abspath(os.path.join(self.output_dir, 'zeek_config.zeek'))

        zeek_cmd = [
            self.zeek_path,
            '-C',
            '-r', pcap_full_path,
            zeek_config_path
        ]

        print(f"Uruchamianie Zeeka z poleceniem: {' '.join(zeek_cmd)}")
        result = subprocess.run(
            zeek_cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )

        if result.returncode != 0:
            print(f"Błąd Zeeka:\n{result.stderr}")
            raise RuntimeError("Przetwarzanie przez Zeeka nie powiodło się. Sprawdź instalację Zeeka i plik PCAP.")
        else:
            print(f"Logi Zeeka wygenerowane w {self.output_dir}")

    def load_logs(self):
        """Ładuje wszystkie logi Zeeka do słownika DataFrame'ów."""
        log_files = glob.glob(os.path.join(self.output_dir, '*.log'))

        for log_file in log_files:
            log_name = os.path.basename(log_file)
            print(f"Ładowanie logu: {log_name}")
            df = self.read_zeek_log(log_file)
            if df is not None:
                self.logs[log_name] = df
            else:
                print(f"Brak danych w {log_name}")

    def read_zeek_log(self, log_file):
        """Odczytuje log Zeeka w formacie JSON i zwraca DataFrame."""
        try:
            # Próba odczytu jako JSON (jeśli logi są w formacie JSON)
            df = pd.read_json(log_file, lines=True)
            return df
        except ValueError:
            print(f"Nie udało się odczytać {log_file} jako JSON. Spróbuję odczytać jako TSV.")
            try:
                # Jeśli JSON się nie uda, spróbuj odczytać jako TSV
                with open(log_file, 'r', encoding='utf-8') as f:
                    lines = f.readlines()

                # Znajdź linię z polami
                fields_line = [line for line in lines if line.startswith('#fields')][0]
                fields = fields_line.strip().split()[1:]

                # Wczytaj dane jako TSV
                df = pd.read_csv(
                    log_file,
                    sep='\t',
                    comment='#',
                    names=fields,
                    header=None,
                    na_values='-',
                    skiprows=[i for i, line in enumerate(lines) if line.startswith('#')]
                )
                return df
            except Exception as e:
                print(f"Nie udało się odczytać {log_file}: {e}")
                return None


    def is_local(self, ip):
        """Sprawdza, czy adres IP należy do sieci lokalnej."""
        try:
            ip_addr = ipaddress.ip_address(ip)
            for net in self.local_nets:
                if ip_addr in ipaddress.ip_network(net):
                    return True
        except ValueError:
            pass  # Nieprawidłowy adres IP
        return False

    def analyze_conn_log(self):
        """Analizuje połączenia z pliku conn.log z kategoryzacją i parametryzacją."""
        conn_log = self.logs.get('conn.log')
        if conn_log is None:
            print("conn.log nie znaleziony w logach.")
            return

        # Kategoryzacja połączeń
        def categorize_connection(row):
            src_ip = row['id.orig_h']
            dst_ip = row['id.resp_h']
            if self.is_local(src_ip) and not self.is_local(dst_ip):
                return 'Wychodzące'
            elif not self.is_local(src_ip) and self.is_local(dst_ip):
                return 'Przychodzące'
            elif self.is_local(src_ip) and self.is_local(dst_ip):
                return 'Wewnetrzne'
            else:
                return 'Zewnetrzne'

        conn_log['kategoria'] = conn_log.apply(categorize_connection, axis=1)

        # Parametryzacja połączeń (np. filtrowanie po czasie trwania, ilości bajtów)
        conn_log['duration'] = conn_log['duration'].astype(float)
        conn_log['orig_bytes'] = conn_log['orig_bytes'].astype(float)
        conn_log['resp_bytes'] = conn_log['resp_bytes'].astype(float)

        # Filtrowanie połączeń na podstawie progów
        conn_log['long_duration'] = conn_log['duration'].apply(lambda x: 'Tak' if x > self.duration_threshold else 'Nie')
        conn_log['large_transfer'] = (conn_log['orig_bytes'] + conn_log['resp_bytes']).apply(lambda x: 'Tak' if x > self.bytes_threshold else 'Nie')

        # Kategoryzacja na podstawie portów (np. standardowe i niestandardowe)
        def port_category(port):
            if 1 <= port <= 1024:
                return 'Standardowy'
            else:
                return 'Niestandardowy'

        conn_log['resp_p'] = conn_log['id.resp_p'].astype(int)
        conn_log['kategoria_portu'] = conn_log['resp_p'].apply(port_category)

        # Zapisanie wyników
        output_file = os.path.join(self.secure_dir, "conn_analysis.csv")
        if not os.path.exists(self.secure_dir):
            os.makedirs(self.secure_dir, mode=0o700)
        conn_log.to_csv(output_file, index=False)
        os.chmod(output_file, 0o600)

        # Wyświetlenie statystyk kategoryzacji
        print("\nStatystyki kategoryzacji połączeń:")
        print(conn_log['kategoria'].value_counts())

        print("\nStatystyki czasu trwania połączeń:")
        print(conn_log['long_duration'].value_counts())

        print("\nStatystyki transferu danych:")
        print(conn_log['large_transfer'].value_counts())

        print("\nStatystyki kategorii portów:")
        print(conn_log['kategoria_portu'].value_counts())

    # Dodane metody dla pozostałych logów

    def analyze_dns_log(self):
        dns_log = self.logs.get('dns.log')
        if dns_log is None:
            print("dns.log nie znaleziony w logach.")
            return

        # Uzupełnij puste wartości i skonwertuj na string
        dns_log['query'] = dns_log['query'].fillna('').astype(str)

        # Wykrywanie zapytań do podejrzanych domen
        def is_suspicious_domain(domain):
            suspicious_tlds = ['.tk', '.cn', '.ru']
            if not domain:  # Jeśli domena jest pusta
                return 'Nie'
            if any(domain.endswith(tld) for tld in suspicious_tlds):
                return 'Tak'
            if len(domain) > 50:
                return 'Tak'
            return 'Nie'

        dns_log['podejrzana_domena'] = dns_log['query'].apply(is_suspicious_domain)

        # Zapisanie wyników
        output_file = os.path.join(self.secure_dir, "dns_analysis.csv")
        if not os.path.exists(self.secure_dir):
            os.makedirs(self.secure_dir, mode=0o700)
        dns_log.to_csv(output_file, index=False)
        os.chmod(output_file, 0o600)

        # Wyświetlenie statystyk
        print("\nStatystyki podejrzanych domen:")
        print(dns_log['podejrzana_domena'].value_counts())


    def analyze_http_log(self):
        """Analizuje żądania HTTP z pliku http.log."""
        http_log = self.logs.get('http.log')
        if http_log is None:
            print("http.log nie znaleziony w logach.")
            return

        # Wykrywanie podejrzanych User-Agentów
        def is_suspicious_user_agent(ua):
            suspicious_agents = ['sqlmap', 'nikto', 'fuzz']
            if pd.notna(ua) and any(agent in ua.lower() for agent in suspicious_agents):
                return 'Tak'
            return 'Nie'

        http_log['podejrzany_user_agent'] = http_log['user_agent'].apply(is_suspicious_user_agent)

        # Wykrywanie zapytań do podejrzanych URLi
        def is_suspicious_uri(uri):
            suspicious_patterns = ['/admin', '/login', '/config', '/cmd']
            if pd.notna(uri) and any(pattern in uri.lower() for pattern in suspicious_patterns):
                return 'Tak'
            return 'Nie'

        http_log['podejrzany_uri'] = http_log['uri'].apply(is_suspicious_uri)

        # Zapisanie wyników
        output_file = os.path.join(self.secure_dir, "http_analysis.csv")
        http_log.to_csv(output_file, index=False)
        os.chmod(output_file, 0o600)

    def analyze_ssl_log(self):
        """Analizuje połączenia SSL z plików ssl.log i x509.log."""
        ssl_log = self.logs.get('ssl.log')
        x509_log = self.logs.get('x509.log')

        # Sprawdzenie dostępności i zawartości logów
        if ssl_log is None or ssl_log.empty:
            print("ssl.log jest pusty lub nie znaleziony. Pomijam analizę SSL.")
            return

        if x509_log is None or x509_log.empty:
            print("x509.log jest pusty lub nie znaleziony. Pomijam analizę SSL.")
            return

        # Sprawdzenie obecności kolumny 'cert_chain_fuids'
        if 'cert_chain_fuids' not in ssl_log.columns:
            print("Kolumna 'cert_chain_fuids' nie istnieje w ssl.log. Pomijam analizę SSL.")
            return

        # Analiza SSL
        ssl_log['cert_id'] = ssl_log['cert_chain_fuids'].str.strip().str.split(',').str[0]
        merged_df = ssl_log.merge(
            x509_log, 
            left_on='cert_id', 
            right_on='id', 
            how='left', 
            suffixes=('_ssl', '_x509')
        )

        # Wykrywanie certyfikatów samopodpisanych
        def is_self_signed(row):
            return 'Tak' if row['issuer'] == row['subject'] else 'Nie'

        merged_df['samopodpisany'] = merged_df.apply(is_self_signed, axis=1)

        # Zapisanie wyników
        output_file = os.path.join(self.secure_dir, "ssl_analysis.csv")
        if not os.path.exists(self.secure_dir):
            os.makedirs(self.secure_dir, mode=0o700)
        merged_df.to_csv(output_file, index=False)
        os.chmod(output_file, 0o600)

        print("Analiza SSL zakończona.")


    def analyze_files_log(self):
        """Analizuje pliki z pliku files.log."""
        files_log = self.logs.get('files.log')
        if files_log is None:
            print("files.log nie znaleziony w logach.")
            return

        # Wykrywanie plików podejrzanych typów
        suspicious_mime_types = ['application/x-dosexec', 'application/x-executable']
        files_log['podejrzany_typ'] = files_log['mime_type'].apply(lambda x: 'Tak' if x in suspicious_mime_types else 'Nie')

        # Ekstrakcja i hashowanie plików
        extracted_files_dir = os.path.join(self.output_dir, 'extract_files')
        if os.path.exists(extracted_files_dir):
            for root, dirs, files in os.walk(extracted_files_dir):
                for file in files:
                    file_path = os.path.join(root, file)
                    # Oblicz hash SHA256
                    sha256_hash = hashlib.sha256()
                    with open(file_path, "rb") as f:
                        for byte_block in iter(lambda: f.read(4096), b""):
                            sha256_hash.update(byte_block)
                    hash_hex = sha256_hash.hexdigest()

                    # Zapisz informacje o pliku
                    files_log.loc[files_log['fuid'] == file, 'sha256'] = hash_hex

                    # Przenieś plik do zabezpieczonego katalogu
                    dest_path = os.path.join(self.secure_dir, 'extracted_files', file)
                    dest_dir = os.path.dirname(dest_path)
                    if not os.path.exists(dest_dir):
                        os.makedirs(dest_dir, mode=0o700)
                    shutil.copy2(file_path, dest_path)
                    os.chmod(dest_path, 0o600)

        # Zapisanie wyników
        output_file = os.path.join(self.secure_dir, "files_analysis.csv")
        files_log.to_csv(output_file, index=False)
        os.chmod(output_file, 0o600)

    def analyze_weird_log(self):
        """Analizuje nietypowe zdarzenia z pliku weird.log."""
        weird_log = self.logs.get('weird.log')
        if weird_log is None:
            print("weird.log nie znaleziony w logach.")
            return

        # Zapisanie wyników
        output_file = os.path.join(self.secure_dir, "weird_analysis.csv")
        weird_log.to_csv(output_file, index=False)
        os.chmod(output_file, 0o600)

    def analyze_notice_log(self):
        """Analizuje powiadomienia z pliku notice.log."""
        notice_log = self.logs.get('notice.log')
        if notice_log is None:
            print("notice.log nie znaleziony w logach.")
            return

        # Zapisanie wyników
        output_file = os.path.join(self.secure_dir, "notice_analysis.csv")
        notice_log.to_csv(output_file, index=False)
        os.chmod(output_file, 0o600)

    def save_analysis(self, output_file='analysis_results.json'):
        """Zapisuje wyniki analizy do pliku JSON."""
        analysis = {}

        for log_name, df in self.logs.items():
            # Konwersja obiektów Timestamp do string
            df = df.copy()  # Tworzymy kopię, aby nie modyfikować oryginalnych danych
            for col in df.select_dtypes(include=['datetime64', 'datetimetz']):
                df[col] = df[col].astype(str)

            # Dla przykładu zapisujemy tylko pierwsze 10 rekordów
            analysis[log_name] = df.head(10).to_dict(orient='records')

        with open(output_file, 'w') as f:
            json.dump(analysis, f, indent=4)
        print(f"Wyniki analizy zapisane w {output_file}")


if __name__ == '__main__':
    # Ścieżka do pliku PCAP
    pcap_file = "data/dns-remoteshell.pcap"
    # pcap_file = "data/snort.log.1425565276"

    # Inicjalizacja analizatora z parametrami
    analyzer = ZeekAnalyzer(
        pcap_file=pcap_file,
        local_nets=['192.168.1.0/24', '10.0.0.0/8'],
        duration_threshold=10.0,
        bytes_threshold=1000,
        output_dir='zeek_logs',
        secure_dir='secure_evidence'
    )

    # Uruchomienie Zeeka
    analyzer.run_zeek()

    # Ładowanie wygenerowanych logów
    analyzer.load_logs()

    # Analiza połączeń
    analyzer.analyze_conn_log()

    # Analiza DNS
    analyzer.analyze_dns_log()

    # Analiza HTTP
    analyzer.analyze_http_log()

    # Analiza SSL
    analyzer.analyze_ssl_log()

    # Analiza plików
    analyzer.analyze_files_log()

    # Analiza weird.log
    analyzer.analyze_weird_log()

    # Analiza notice.log
    analyzer.analyze_notice_log()

    # Zapisanie wyników analizy
    analyzer.save_analysis('wyniki_analizy.json')
