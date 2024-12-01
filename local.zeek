@load protocols/ftp
@load protocols/http
@load protocols/smb

redef FileExtraction::default_file_broker_store_dir = "extract_files";
event FileExtraction::extract(f: fa_file) { }
