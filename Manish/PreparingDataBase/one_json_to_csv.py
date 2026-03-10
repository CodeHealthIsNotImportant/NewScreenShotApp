import json
import csv

with open("sample.json", encoding="utf-8") as f:
    data = json.load(f)

cve_id = data["cveMetadata"]["cveId"]
state = data["cveMetadata"]["state"]
published = data["cveMetadata"]["datePublished"]
updated = data["cveMetadata"]["dateUpdated"]

affected = data["containers"]["cna"]["affected"][0]
vendor = affected.get("vendor", "n/a")
product = affected.get("product", "n/a")
version = affected["versions"][0].get("version", "n/a")

description = data["containers"]["cna"]["descriptions"][0]["value"]

references = data["containers"]["cna"]["references"]
ref_urls = "|".join(ref["url"] for ref in references)

with open("output.csv", "w", newline="", encoding="utf-8") as csvfile:
    writer = csv.writer(csvfile)
    writer.writerow([
        "CVE_ID",
        "State",
        "Date_Published",
        "Date_Updated",
        "Vendor",
        "Product",
        "Affected_Version",
        "Description",
        "References"
    ])
    writer.writerow([
        cve_id,
        state,
        published,
        updated,
        vendor,
        product,
        version,
        description,
        ref_urls
    ])

print("CSV created: output.csv")

