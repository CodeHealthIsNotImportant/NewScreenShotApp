import json
from pathlib import Path
from datetime import datetime

import yaml
import pandas as pd
import psycopg2


BASE_DIR = Path("/opt/vuln-phase1")
OUTPUT_DIR = BASE_DIR / "output"
CONFIG_FILE = BASE_DIR / "config" / "config.yaml"


def load_config():
    with open(CONFIG_FILE, "r") as f:
        return yaml.safe_load(f)  #converts yaml to dictionary,{db:{"":""}}


def get_conn():
    cfg = load_config()["db"] #pulls the dict in db:
    return psycopg2.connect(  #calls the postgrese driver ask to open a db connection
        host=cfg["host"],
        port=cfg["port"],
        dbname=cfg["name"],
        user=cfg["user"],
        password=cfg["password"],
        connect_timeout=10
    )


#Takes a scan file (Excel or CSV) and returns a clean pandas DataFrame with the correct header row.
def load_report(file_path: Path) -> pd.DataFrame:
    if file_path.suffix.lower() == ".xlsx":
        SHEET = "Scan Output & Analysis"

        preview = pd.read_excel(
            file_path,
            sheet_name=SHEET,
            dtype=str,  #every cell to be a string.
            engine="openpyxl",
            # header=None,  #Do NOT treat any row as column headers.
            # nrows=80
            header=None,  #Do NOT treat any row as column headers.
            #nrows=80
        )

        header_row = None
        for i in range(len(preview)):  
            #Clean the row
            row = (
                preview.iloc[i]  #get row i
                .dropna()
                .astype(str)
                .str.strip()
                .str.lower()
                .tolist()
            )
            if not row:
                continue
            if any("plugin id" in cell for cell in row):
                header_row = i
                break

        if header_row is None:
            raise ValueError("Could not detect header row containing 'Plugin ID' in Excel sheet")

        df = pd.read_excel(
            file_path,
            sheet_name=SHEET,
            dtype=str,
            engine="openpyxl",
            header=header_row
        )
    else:
        df = pd.read_csv(
            file_path,
            dtype=str,
            encoding_errors="ignore",
            sep=None,
            engine="python"
        )

    df.columns = [str(c).strip() for c in df.columns]
    return df


def normalize_plugin_fields(df: pd.DataFrame) -> pd.DataFrame:
    df.columns = [str(c).strip() for c in df.columns] #Converts all column names to strings and strips whitespace
    cols_lower = {c.lower().strip(): c for c in df.columns}  #dictionary of lower lower things:real things

    # Plugin ID
    if "plugin id" in cols_lower:
        plugin_id_col = cols_lower["plugin id"]
    elif "pluginid" in cols_lower:
        plugin_id_col = cols_lower["pluginid"]
    elif "plugin_id" in cols_lower:
        plugin_id_col = cols_lower["plugin_id"]
    else:
        raise ValueError(f"Missing required column: Plugin ID. Found columns: {list(df.columns)}")

    # Plugin Title
    plugin_title_col = None
    for candidate in ["plugin title", "plugin name", "plugin", "vulnerability", "name"]:
        if candidate in cols_lower:
            plugin_title_col = cols_lower[candidate]
            break

    # Asset Name
    asset_col = None
    for candidate in ["asset name", "asset", "host", "hostname", "ip address"]:
        if candidate in cols_lower:
            asset_col = cols_lower[candidate]
            break
    if not asset_col:
        raise ValueError(f"Missing required column: Asset Name. Found columns: {list(df.columns)}")

    # Risk Factor col (needed for override)
    risk_col = None
    for candidate in ["risk factor", "severity", "priority"]:
        if candidate in cols_lower:
            risk_col = cols_lower[candidate]
            break
    if not risk_col:
        raise ValueError(f"Missing required column: Risk Factor. Found columns: {list(df.columns)}")

    df["__plugin_id"] = pd.to_numeric(df[plugin_id_col], errors="coerce").astype("Int64")
    df["__plugin_title"] = df[plugin_title_col].astype(str).str.strip() if plugin_title_col else ""
    df["__asset_name"] = df[asset_col].astype(str).str.strip()
    df["__risk_factor"] = df[risk_col].astype(str).str.strip()

    df = df.dropna(subset=["__plugin_id"])
    df["__plugin_id"] = df["__plugin_id"].astype(int)

    df = df[df["__asset_name"].notna() & (df["__asset_name"].str.len() > 0)]

    return df


def db_plugin_asset_exists(conn, plugin_id: int, asset_name: str) -> bool:
    with conn.cursor() as cur:
        cur.execute(
            "SELECT 1 FROM vuln_rows WHERE plugin_id=%s AND asset_name=%s LIMIT 1;",
            (plugin_id, asset_name)
        )
        return cur.fetchone() is not None


def db_get_risk_override(conn, plugin_id: int):
    with conn.cursor() as cur:
        cur.execute(
            "SELECT risk_factor_override FROM risk_overrides WHERE plugin_id=%s;",
            (plugin_id,)
        )
        r = cur.fetchone()
        return r[0] if r else None


def db_insert_row(conn, plugin_id: int, plugin_title: str, asset_name: str, raw_row: dict):
    with conn.cursor() as cur:
        cur.execute(
            """
            INSERT INTO vuln_rows (plugin_id, plugin_title, asset_name, raw_row)
            VALUES (%s, %s, %s, %s::jsonb);
            """,
            (plugin_id, plugin_title, asset_name, json.dumps(raw_row)),
        )


def process_file(file_path: Path):
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    df = load_report(file_path)
    df = normalize_plugin_fields(df)

    total = len(df)

    new_rows = []
    old_rows = []

    conn = get_conn()
    conn.autocommit = False

    try:
        for _, row in df.iterrows():
            plugin_id = int(row["__plugin_id"])
            plugin_title = str(row["__plugin_title"])
            asset_name = str(row["__asset_name"]).strip()

            # override risk factor if exists
            original_risk = str(row["__risk_factor"])
            override_risk = db_get_risk_override(conn, plugin_id)
            final_risk = override_risk if override_risk else original_risk

            raw_row = {
                k: (None if pd.isna(v) else str(v))
                for k, v in row.drop(labels=["__plugin_id", "__plugin_title", "__asset_name", "__risk_factor"]).items()
            }

            # Ensure risk factor in output is corrected
            raw_row["Risk Factor"] = final_risk
            raw_row["Asset Name"] = asset_name
            raw_row["Plugin ID"] = plugin_id
            raw_row["Plugin Title"] = plugin_title

            if db_plugin_asset_exists(conn, plugin_id, asset_name):
                old_rows.append(raw_row)
            else:
                new_rows.append({
                    "Plugin ID": plugin_id,
                    "Plugin Title": plugin_title,
                    "Asset Name": asset_name,
                    "Risk Factor (Final)": final_risk,
                    "Risk Factor (Original)": original_risk
                })

            db_insert_row(conn, plugin_id, plugin_title, asset_name, raw_row)

        conn.commit()

    except Exception:
        conn.rollback()
        raise

    finally:
        conn.close()

    month = datetime.now().strftime("%Y-%m")
    stem = file_path.stem

    out_file = OUTPUT_DIR / f"{month}_{stem}_results.xlsx"

    summary_df = pd.DataFrame([{
        "Input File": file_path.name,
        "Total Rows Scanned": total,
        "Old Vulnerabilities": len(old_rows),
        "New Vulnerabilities": len(new_rows),
        "Generated At": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    }])

    new_df = pd.DataFrame(new_rows)
    old_df = pd.DataFrame(old_rows)

    with pd.ExcelWriter(out_file, engine="xlsxwriter") as writer:
        summary_df.to_excel(writer, sheet_name="Summary", index=False)
        new_df.to_excel(writer, sheet_name="New Vulnerabilities", index=False)
        old_df.to_excel(writer, sheet_name="Old Vulnerabilities", index=False)

        workbook = writer.book
        header_format = workbook.add_format({"bold": True})

        for sheet_name in ["Summary", "New Vulnerabilities", "Old Vulnerabilities"]:
            ws = writer.sheets[sheet_name]
            ws.set_row(0, None, header_format)
            ws.freeze_panes(1, 0)

    print(f"[OK] File processed: {file_path.name}")
    print(f"[OK] Total rows scanned: {total}")
    print(f"[OK] Old vulnerabilities: {len(old_rows)}")
    print(f"[OK] New vulnerabilities: {len(new_rows)}")
    print(f"[OK] Excel report generated: {out_file}")

