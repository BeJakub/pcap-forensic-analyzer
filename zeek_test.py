import os
import subprocess
import glob
import json
import pandas as pd
import ipaddress
import hashlib
import shutil
from datetime import datetime
from scapy.all import rdpcap, PcapReader
from cryptography.fernet import Fernet

class ZeekAnalyzer:
    def __init__(self, pcap_file, zeek_path='zeek', output_dir='zeek_logs', secure_dir='secure_evidence',
                 local_nets=None, duration_threshold=10.0, bytes_threshold=1000):
        self.pcap_file = pcap_file
        self.zeek_path = zeek_path
        self.output_dir = output_dir
        self.secure_dir = secure_dir
        self.logs = {}
        self.local_nets = local_nets or ['192.168.1.0/24']
        self.duration_threshold = duration_threshold
        self.bytes_threshold = bytes_threshold
        self.analysis_results = {}

        # Generowanie klucza do szyfrowania danych
        self.encryption_key = Fernet.generate_key()
        self.cipher_suite = Fernet(self.encryption_key)

    def run_zeek(self):
        """Uruchamia Zeeka na pliku PCAP z użyciem zeek_config.zeek."""
        if not os.path.exists(self.output_dir):
            os.makedirs(self.output_dir)

        pcap_full_path = os.path.abspath(self.pcap_file)
        zeek_config_path = os.path.abspath(os.path.join(self.output_dir, 'zeek_config.zeek'))

        # Upewnij się, że plik zeek_config.zeek istnieje
        if not os.path.exists(zeek_config_path):
            with open(zeek_config_path, 'w') as f:
                f.write(f'redef LogAscii::use_json = T;\n')
                f.write(f'redef Log::default_logdir = "{self.output_dir}";\n')
                # Możesz dodać dodatkowe redefinicje w razie potrzeby

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
            if df is not None and not df.empty:
                self.logs[log_name] = df
            else:
                print(f"Brak danych w {log_name}")

    def read_zeek_log(self, log_file):
        """Odczytuje log Zeeka w formacie JSON i zwraca DataFrame."""
        try:
            df = pd.read_json(log_file, lines=True)
            return df
        except ValueError:
            print(f"Nie udało się odczytać {log_file} jako JSON. Spróbuję odczytać jako TSV.")
            try:
                with open(log_file, 'r', encoding='utf-8') as f:
                    lines = f.readlines()

                fields_line = [line for line in lines if line.startswith('#fields')][0]
                fields = fields_line.strip().split()[1:]

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
            pass
        return False

    def analyze_pcap_file(self):
        """Analizuje podstawowe cechy pliku PCAP."""
        print("Analiza pliku PCAP...")
        pcap_size = os.path.getsize(self.pcap_file)
        packet_count = 0
        protocols = set()
        timestamps = []

        with PcapReader(self.pcap_file) as pcap_reader:
            for pkt in pcap_reader:
                packet_count += 1
                if 'IP' in pkt:
                    protocols.add(pkt['IP'].proto)
                if hasattr(pkt, 'time'):
                    timestamps.append(float(pkt.time))

        start_time = datetime.fromtimestamp(min(timestamps)) if timestamps else None
        end_time = datetime.fromtimestamp(max(timestamps)) if timestamps else None

        self.analysis_results['pcap_info'] = {
            'file_size_bytes': pcap_size,
            'packet_count': packet_count,
            'start_time': start_time.strftime('%Y-%m-%d %H:%M:%S') if start_time else 'Unknown',
            'end_time': end_time.strftime('%Y-%m-%d %H:%M:%S') if end_time else 'Unknown',
            'protocols': list(protocols)
        }

        print("Analiza pliku PCAP zakończona.")

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

        # Parametryzacja połączeń
        conn_log['duration'] = pd.to_numeric(conn_log['duration'], errors='coerce')
        conn_log['orig_bytes'] = pd.to_numeric(conn_log['orig_bytes'], errors='coerce')
        conn_log['resp_bytes'] = pd.to_numeric(conn_log['resp_bytes'], errors='coerce')

        conn_log['long_duration'] = conn_log['duration'].apply(lambda x: 'Tak' if x > self.duration_threshold else 'Nie')
        conn_log['large_transfer'] = (conn_log['orig_bytes'] + conn_log['resp_bytes']).apply(
            lambda x: 'Tak' if x > self.bytes_threshold else 'Nie')

        # Kategoryzacja na podstawie portów
        conn_log['resp_p'] = pd.to_numeric(conn_log['id.resp_p'], errors='coerce')
        conn_log['kategoria_portu'] = conn_log['resp_p'].apply(lambda x: 'Standardowy' if 1 <= x <= 1024 else 'Niestandardowy')

        # Hashowanie adresów IP dla bezpieczeństwa
        conn_log['id.orig_h'] = conn_log['id.orig_h'].apply(lambda x: self.cipher_suite.encrypt(x.encode()).decode())
        conn_log['id.resp_h'] = conn_log['id.resp_h'].apply(lambda x: self.cipher_suite.encrypt(x.encode()).decode())

        # Zapisanie wyników
        output_file = os.path.join(self.secure_dir, "conn_analysis.csv")
        if not os.path.exists(self.secure_dir):
            os.makedirs(self.secure_dir, mode=0o700)
        conn_log.to_csv(output_file, index=False)
        os.chmod(output_file, 0o600)

        # Statystyki
        self.analysis_results['conn_stats'] = {
            'kategoria': conn_log['kategoria'].value_counts().to_dict(),
            'long_duration': conn_log['long_duration'].value_counts().to_dict(),
            'large_transfer': conn_log['large_transfer'].value_counts().to_dict(),
            'kategoria_portu': conn_log['kategoria_portu'].value_counts().to_dict(),
            'protocols': conn_log['proto'].value_counts().to_dict()
        }

        print("Analiza conn.log zakończona.")

    def analyze_dns_log(self):
        """Analizuje zapytania DNS z pliku dns.log."""
        dns_log = self.logs.get('dns.log')
        if dns_log is None:
            print("dns.log nie znaleziony w logach.")
            return

        dns_log['query'] = dns_log['query'].fillna('').astype(str)

        def is_suspicious_domain(domain):
            suspicious_tlds = ['.tk', '.cn', '.ru']
            if not domain:
                return 'Nie'
            if any(domain.endswith(tld) for tld in suspicious_tlds):
                return 'Tak'
            if len(domain) > 50:
                return 'Tak'
            return 'Nie'

        dns_log['podejrzana_domena'] = dns_log['query'].apply(is_suspicious_domain)

        # Zapisanie wyników
        output_file = os.path.join(self.secure_dir, "dns_analysis.csv")
        dns_log.to_csv(output_file, index=False)
        os.chmod(output_file, 0o600)

        # Statystyki
        self.analysis_results['dns_stats'] = dns_log['podejrzana_domena'].value_counts().to_dict()

        print("Analiza dns.log zakończona.")

    def analyze_http_log(self):
        """Analizuje żądania HTTP z pliku http.log."""
        http_log = self.logs.get('http.log')
        if http_log is None:
            print("http.log nie znaleziony w logach.")
            return

        def is_suspicious_user_agent(ua):
            suspicious_agents = ['sqlmap', 'nikto', 'fuzz']
            if pd.notna(ua) and any(agent in ua.lower() for agent in suspicious_agents):
                return 'Tak'
            return 'Nie'

        http_log['podejrzany_user_agent'] = http_log['user_agent'].apply(is_suspicious_user_agent)

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

        # Statystyki
        self.analysis_results['http_stats'] = {
            'podejrzany_user_agent': http_log['podejrzany_user_agent'].value_counts().to_dict(),
            'podejrzany_uri': http_log['podejrzany_uri'].value_counts().to_dict()
        }

        print("Analiza http.log zakończona.")

    def analyze_ssl_log(self):
        """Analizuje połączenia SSL z plików ssl.log i x509.log."""
        ssl_log = self.logs.get('ssl.log')
        x509_log = self.logs.get('x509.log')

        if ssl_log is None or ssl_log.empty:
            print("ssl.log jest pusty lub nie znaleziony. Pomijam analizę SSL.")
            return

        if x509_log is None or x509_log.empty:
            print("x509.log jest pusty lub nie znaleziony. Pomijam analizę SSL.")
            return

        if 'cert_chain_fuids' not in ssl_log.columns:
            print("Kolumna 'cert_chain_fuids' nie istnieje w ssl.log. Pomijam analizę SSL.")
            return

        ssl_log['cert_id'] = ssl_log['cert_chain_fuids'].str.strip().str.split(',').str[0]
        merged_df = ssl_log.merge(
            x509_log,
            left_on='cert_id',
            right_on='id',
            how='left',
            suffixes=('_ssl', '_x509')
        )

        def is_self_signed(row):
            return 'Tak' if row['issuer'] == row['subject'] else 'Nie'

        merged_df['samopodpisany'] = merged_df.apply(is_self_signed, axis=1)

        # Zapisanie wyników
        output_file = os.path.join(self.secure_dir, "ssl_analysis.csv")
        merged_df.to_csv(output_file, index=False)
        os.chmod(output_file, 0o600)

        # Statystyki
        self.analysis_results['ssl_stats'] = merged_df['samopodpisany'].value_counts().to_dict()

        print("Analiza SSL zakończona.")

    def analyze_files_log(self):
        """Analizuje pliki z pliku files.log."""
        files_log = self.logs.get('files.log')
        if files_log is None:
            print("files.log nie znaleziony w logach.")
            return

        suspicious_mime_types = ['application/x-dosexec', 'application/x-executable']
        files_log['podejrzany_typ'] = files_log['mime_type'].apply(lambda x: 'Tak' if x in suspicious_mime_types else 'Nie')

        extracted_files_dir = os.path.join(self.output_dir, 'extract_files')
        if os.path.exists(extracted_files_dir):
            for root, dirs, files in os.walk(extracted_files_dir):
                for file in files:
                    file_path = os.path.join(root, file)
                    sha256_hash = hashlib.sha256()
                    with open(file_path, "rb") as f:
                        for byte_block in iter(lambda: f.read(4096), b""):
                            sha256_hash.update(byte_block)
                    hash_hex = sha256_hash.hexdigest()

                    files_log.loc[files_log['fuid'] == file, 'sha256'] = hash_hex

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

        print("Analiza files.log zakończona.")

    def analyze_weird_log(self):
        """Analizuje nietypowe zdarzenia z pliku weird.log."""
        weird_log = self.logs.get('weird.log')
        if weird_log is None:
            print("weird.log nie znaleziony w logach.")
            return

        output_file = os.path.join(self.secure_dir, "weird_analysis.csv")
        weird_log.to_csv(output_file, index=False)
        os.chmod(output_file, 0o600)

        print("Analiza weird.log zakończona.")

    def analyze_notice_log(self):
        """Analizuje powiadomienia z pliku notice.log."""
        notice_log = self.logs.get('notice.log')
        if notice_log is None:
            print("notice.log nie znaleziony w logach.")
            return

        output_file = os.path.join(self.secure_dir, "notice_analysis.csv")
        notice_log.to_csv(output_file, index=False)
        os.chmod(output_file, 0o600)

        print("Analiza notice.log zakończona.")

    def save_analysis(self, output_file='analysis_results.json'):
        """Zapisuje wyniki analizy do pliku JSON."""
        with open(output_file, 'w') as f:
            json.dump(self.analysis_results, f, indent=4)
        os.chmod(output_file, 0o600)
        print(f"Wyniki analizy zapisane w {output_file}")

    def run_full_analysis(self):
        """Wykonuje pełną analizę."""
        self.analyze_pcap_file()
        self.analyze_conn_log()
        self.analyze_dns_log()
        self.analyze_http_log()
        self.analyze_ssl_log()
        self.analyze_files_log()
        self.analyze_weird_log()
        self.analyze_notice_log()
        self.save_analysis('wyniki_analizy.json')

if __name__ == '__main__':
    # Ścieżka do pliku PCAP
    pcap_file = "data/snort.log.1428883207"

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

    # Wykonanie pełnej analizy
    analyzer.run_full_analysis()
