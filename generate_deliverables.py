"""Script to directly generate complete, professional PPTX slides and DOCX assessment reports.
Places output files directly into the project folders and root for easy access and manual editing.
"""

from __future__ import annotations
import sys
from pathlib import Path

# Add project root to sys.path
BASE_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(BASE_DIR))

from src.storage.scan_store import ScanStore
from src.presentation.pptx_deck import generate_presentation
from src.reporting.docx_report import generate_docx_report
from src.reporting.exporter import export_json, export_csv_bundle
from capture_screenshots import create_demo_assessment


def generate_all_deliverables():
    store = ScanStore()
    
    # Check if there is an existing scan, or use the rich demo assessment
    latest_scan = store.get_latest()
    if not latest_scan:
        print("[*] Creating demo assessment...")
        latest_scan = create_demo_assessment()
        store.save(latest_scan)

    print(f"[+] Using assessment: ID={latest_scan.id}, Target={latest_scan.target}, Hosts={len(latest_scan.hosts)}, Findings={len(latest_scan.all_findings)}")

    # 1. Output destinations
    pptx_folder_dest = BASE_DIR / "presentations" / "generated" / "ShieldScan_Presentation.pptx"
    pptx_root_dest = BASE_DIR / "presentations" / "ShieldScan_Presentation.pptx"
    
    docx_folder_dest = BASE_DIR / "reports" / "generated" / "ShieldScan_Network_Assessment.docx"
    docx_root_dest = BASE_DIR / "reports" / "ShieldScan_Network_Assessment.docx"
    
    csv_dir = BASE_DIR / "exports" / "csv"
    json_path = BASE_DIR / "exports" / "json" / "ShieldScan_Assessment_Model.json"
    screenshots_dir = BASE_DIR / "screenshots"

    # 2. Generate PPTX
    print(f"[*] Generating PowerPoint presentation to {pptx_folder_dest}...")
    generate_presentation(latest_scan, pptx_folder_dest, screenshots_dir=screenshots_dir)
    
    # Also save copy in presentations root
    pptx_root_dest.parent.mkdir(parents=True, exist_ok=True)
    with open(pptx_folder_dest, "rb") as f_src, open(pptx_root_dest, "wb") as f_dst:
        f_dst.write(f_src.read())
    print(f"[OK] PPTX generated successfully: {pptx_root_dest.stat().st_size / 1024:.1f} KB")

    # 3. Generate DOCX
    print(f"[*] Generating Word assessment report to {docx_folder_dest}...")
    generate_docx_report(latest_scan, docx_folder_dest)
    
    # Also save copy in reports root
    docx_root_dest.parent.mkdir(parents=True, exist_ok=True)
    with open(docx_folder_dest, "rb") as f_src, open(docx_root_dest, "wb") as f_dst:
        f_dst.write(f_src.read())
    print(f"[OK] DOCX generated successfully: {docx_root_dest.stat().st_size / 1024:.1f} KB")

    # 4. Generate CSV Suite and JSON Export
    print(f"[*] Exporting CSV bundle and JSON...")
    export_json(latest_scan, json_path)
    export_csv_bundle(latest_scan, csv_dir)
    print(f"[OK] JSON and CSV exports ready in {BASE_DIR / 'exports'}")


    print("\n" + "="*70)
    print("ALL DELIVERABLES SUCCESSFULLY GENERATED:")
    print(f"1. PowerPoint Presentation: {pptx_root_dest}")
    print(f"2. Word Assessment Report:   {docx_root_dest}")
    print(f"3. Presentations Folder:    {pptx_folder_dest}")
    print(f"4. Reports Folder:          {docx_folder_dest}")
    print("="*70)


if __name__ == "__main__":
    generate_all_deliverables()
