@load base/protocols/conn
@load base/protocols/http

# Włącz logi w formacie JSON
redef LogAscii::use_json = T;

# Ścieżka, gdzie będą zapisywane logi
redef Log::default_logdir = "/home/jakub-is/Projects/IS - PCAP/zeek_logs";
