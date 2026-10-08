import csv
import io
from decimal import Decimal
from flask import Response

def _json_safe(v):
    if isinstance(v, Decimal):
        return float(v)
    return v

def rows_with_tb_conversion(rows, mb_fields=None, gb_fields=None):
    mb_fields = set(mb_fields or [])
    gb_fields = set(gb_fields or [])
    out = []
    for row in rows or []:
        r = dict(row)
        for field in mb_fields:
            if r.get(field) is not None:
                r[field.replace("_mb", "_tb")] = round(float(r[field]) / 1024 / 1024, 4)
        for field in gb_fields:
            if r.get(field) is not None:
                r[field.replace("_gb", "_tb")] = round(float(r[field]) / 1024, 4)
        out.append({k: _json_safe(v) for k, v in r.items()})
    return out

def _ordered_rows(rows, columns=None):
    if not rows:
        return [], []
    if columns:
        headers = list(columns)
    else:
        headers = list(rows[0].keys())
    return headers, rows

def build_export_response(rows, fmt="csv", base_filename="export",
                          columns=None, sheet_name="Sheet1"):
    fmt = (fmt or "csv").lower()
    headers, data = _ordered_rows(rows, columns)

    if fmt == "xlsx":
        try:
            from openpyxl import Workbook
        except ImportError:
            return Response("openpyxl is required for XLSX export", status=500)
        wb = Workbook()
        ws = wb.active
        ws.title = sheet_name[:31]
        ws.append(headers)
        for row in data:
            ws.append([_json_safe(row.get(h)) for h in headers])
        bio = io.BytesIO()
        wb.save(bio)
        bio.seek(0)
        return Response(
            bio.getvalue(),
            mimetype="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
            headers={"Content-Disposition": f'attachment; filename="{base_filename}.xlsx"'}
        )

    sio = io.StringIO(newline="")
    writer = csv.writer(sio)
    if headers:
        writer.writerow(headers)
        for row in data:
            writer.writerow([_json_safe(row.get(h)) for h in headers])
    return Response(
        sio.getvalue(),
        mimetype="text/csv; charset=utf-8",
        headers={"Content-Disposition": f'attachment; filename="{base_filename}.csv"'}
    )

def build_multi_sheet_export_response(sheets, base_filename="export"):
    try:
        from openpyxl import Workbook
    except ImportError:
        return Response("openpyxl is required for XLSX export", status=500)
    wb = Workbook()
    first = True
    for sheet_name, rows in (sheets or {}).items():
        ws = wb.active if first else wb.create_sheet()
        first = False
        ws.title = str(sheet_name)[:31]
        headers = list(rows[0].keys()) if rows else []
        if headers:
            ws.append(headers)
            for row in rows:
                ws.append([_json_safe(row.get(h)) for h in headers])
    bio = io.BytesIO()
    wb.save(bio)
    bio.seek(0)
    return Response(
        bio.getvalue(),
        mimetype="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        headers={"Content-Disposition": f'attachment; filename="{base_filename}.xlsx"'}
    )
