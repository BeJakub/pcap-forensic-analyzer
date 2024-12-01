# pcap-forensic-analyzer

## Opis projektu

**pcap-forensic-analyzer** to system umożliwiający ekstrakcję danych ze zrzutów transmisji sieciowych w formacie PCAP. Projekt skupia się na analizie zawartości danych, detekcji połączeń wychodzących i przychodzących oraz zabezpieczaniu i kategoryzacji uzyskanych informacji.

## Funkcje systemu

1. **Przetwarzanie plików PCAP**  
   - Wyświetlanie podstawowych cech plików (rozmiar, czas trwania, liczba pakietów).
   - Analiza zawartości danych (protokoły, źródła i cele ruchu, porty).

2. **Detekcja połączeń**  
   - Identyfikacja połączeń wychodzących i przychodzących.
   - Parametryzacja połączeń (adres IP, port, protokół, czas).

3. **Zabezpieczanie danych**  
   - Eksport wyselekcjonowanych danych w formacie CSV/JSON.
   - Mechanizmy zabezpieczające integralność i poufność uzyskanych informacji.

4. **Kategoryzacja danych**  
   - Grupowanie danych według protokołów, adresów IP, lub innych kryteriów.


## Jak używać

1. Umieść plik PCAP w folderze `input/`.
2. Uruchom skrypt analizy:  
   ```bash
   python analyze_pcap.py --file input/nazwa_pliku.pcap
