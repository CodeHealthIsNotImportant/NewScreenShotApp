import json 
import csv 
from pathlib import Path 
INPUT_ROOT = Path("input_json") 
OUTPUT_DIR = Path("output") 
OUTPUT_FILE = OUTPUT_DIR / "all_cves.csv" 
OUTPUT_DIR.mkdir(exist_ok=True) 
def safe_get(obj, *keys): 
    for key in keys: 

        if isinstance(obj, dict): 

            obj = obj.get(key) 

        elif isinstance(obj, list) and isinstance(key, int) and len(obj) > key: 

            obj = obj[key] 

        else: 

            return None 

    return obj 
with open(OUTPUT_FILE, "w", newline="", encoding="utf-8") as csvfile: 

    fieldnames = [ 

        "cve_id", 

        "year", 

        "published_date", 

        "last_updated", 

        "description", 

        "vendor", 

        "product", 

        "cvss_score", 

        "severity", 

        "source_file" 

    ] 

 

    writer = csv.DictWriter(csvfile, fieldnames=fieldnames) 

    writer.writeheader() 

    count = 0 

    failed = 0 

 

    for json_file in INPUT_ROOT.rglob("CVE-*.json"): 

        try: 

            with open(json_file, "r", encoding="utf-8") as f: 

                data = json.load(f) 

 

            cve_id = safe_get(data, "cveMetadata", "cveId") 

            year = cve_id.split("-")[1] if cve_id else None 

 

            row = { 

                "cve_id": cve_id, 

                "year": year, 

                "published_date": safe_get(data, "cveMetadata", "datePublished"), 

                "last_updated": safe_get(data, "cveMetadata", "dateUpdated"), 

                "description": safe_get( 

                    data, "containers", "cna", "descriptions", 0, "value" 

                ), 

                "vendor": safe_get( 

                    data, "containers", "cna", "affected", 0, "vendor" 

                ), 

                "product": safe_get( 

                    data, "containers", "cna", "affected", 0, "product" 

                ), 

                "cvss_score": safe_get( 

                    data, "containers", "cna", "metrics", 0, "cvssV3_1", "baseScore" 

                ), 

                "severity": safe_get( 

                    data, "containers", "cna", "metrics", 0, "cvssV3_1", "baseSeverity" 

                ), 

                "source_file": str(json_file) 

            } 

 

            writer.writerow(row) 

            count += 1 

 

            if count % 1000 == 0: 

                print(f"[+] Processed {count} CVEs...") 

 

        except Exception as e: 

            failed += 1 

            print(f"[✗] Failed {json_file}: {e}") 

 

print("\n==============================") 

print(f"Done") 

print(f"   CVEs processed : {count}") 

print(f"   Failed files   : {failed}") 

print(f"   Output CSV     : {OUTPUT_FILE}") 

print("==============================") 

 