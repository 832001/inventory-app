// ═══════════════════════════════════════════════════════════
//  UTILITIES
// ═══════════════════════════════════════════════════════════

/**
 * Export any HTML table to CSV and trigger a download on the user's device.
 * Strips HTML tags from cells so progress bars / links don't corrupt the file.
 * @param {string} tableId   - id of the <table> or <tbody> element
 * @param {string} filename  - desired filename (e.g. "hosts.csv")
 */
function exportTableToCSV(tableId, filename) {
    const table = document.getElementById(tableId);
    if (!table) { alert("Table not found"); return; }

    const rows  = table.closest("table")
                       ? table.closest("table").querySelectorAll("tr")
                       : table.querySelectorAll("tr");

    const csvLines = [];
    rows.forEach(row => {
        const cells = row.querySelectorAll("th, td");
        const line  = Array.from(cells).map(cell => {
            // Strip HTML, trim, wrap in quotes if contains comma/quote/newline
            let text = cell.innerText.replace(/\n/g, " ").trim();
            if (text.includes(",") || text.includes('"') || text.includes("\n")) {
                text = '"' + text.replace(/"/g, '""') + '"';
            }
            return text;
        }).join(",");
        csvLines.push(line);
    });

    const blob = new Blob(["\uFEFF" + csvLines.join("\n")], // BOM for Excel UTF-8
                          { type: "text/csv;charset=utf-8;" });
    const url  = URL.createObjectURL(blob);
    const a    = document.createElement("a");
    a.href     = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
}

/**
 * Live search/filter on a tbody — hides rows that don't match.
 * @param {string} inputId  - id of the search <input>
 * @param {string} tbodyId  - id of the <tbody> to filter
 */
function liveSearch(inputId, tbodyId) {
    const input = document.getElementById(inputId);
    const tbody = document.getElementById(tbodyId);
    if (!input || !tbody) return;

    input.addEventListener("input", () => {
        const q = input.value.toLowerCase().trim();
        tbody.querySelectorAll("tr").forEach(row => {
            row.style.display = row.innerText.toLowerCase().includes(q) ? "" : "none";
        });
    });
}


// ═══════════════════════════════════════════════════════════
//  NAVIGATION
// ═══════════════════════════════════════════════════════════


// ═══════════════════════════════════════════════════════════
//  DASHBOARD
// ═══════════════════════════════════════════════════════════


// ═══════════════════════════════════════════════════════════
//  VCENTERS
// ═══════════════════════════════════════════════════════════
if (window.location.pathname === "/vcenters") {
    fetch("/api/vcenters")
        .then(res => res.json())
        .then(data => {
            const table = document.getElementById("vcentersTable");
            table.innerHTML = "";
            data.forEach(vc => {
                table.innerHTML += `
                    <tr>
                        <td>${vc.vcenter_name}</td>
                        <td>${vc.hostname}</td>
                        <td>${vc.ip_address || "-"}</td>
                    </tr>`;
            });
        });
}


// ═══════════════════════════════════════════════════════════
//  HOSTS
//  Fix: filter by cluster dropdown change re-fetches with
//       the currently selected run_id, not from URL only
// ═══════════════════════════════════════════════════════════



// ═══════════════════════════════════════════════════════════
//  VMs  —  server-side pagination + search
//  3000+ rows: only 100 loaded at a time, search hits the DB
// ═══════════════════════════════════════════════════════════


// ═══════════════════════════════════════════════════════════
//  DATASTORES
// ═══════════════════════════════════════════════════════════

// ═══════════════════════════════════════════════════════════
//  DATASTORE VMs
// ═══════════════════════════════════════════════════════════
// ═══════════════════════════════════════════════════════════
//  RUN SCRIPT
// ═══════════════════════════════════════════════════════════
function runScript() {
    const out = document.getElementById("scriptOutput");
    out.innerHTML = "Running script...\n";
    fetch("/api/run_script", { method: "POST" })
        .then(res => res.json())
        .then(data => {
            if (data.status === "success") {
                out.innerHTML =
                    "=== STDOUT ===\n" + data.stdout +
                    "\n\n=== STDERR ===\n" + data.stderr +
                    "\n\nReturn Code: " + data.returncode;
            } else {
                out.innerHTML = "Error: " + data.error;
            }
        })
        .catch(err => { out.innerHTML = "Request Failed: " + err; });
}


// ═══════════════════════════════════════════════════════════
//  SHARED: loadRunFilter
// ═══════════════════════════════════════════════════════════
function loadRunFilter(callback) {
    fetch("/api/dashboard")
        .then(res => res.json())
        .then(data => {
            const runSelect = document.getElementById("runFilter");
            if (!runSelect) { if (callback) callback(); return; }

            runSelect.innerHTML = "";
            data.runs.forEach(run => {
                runSelect.innerHTML +=
                    `<option value="${run.run_id}">Run ${run.run_id} - ${run.run_timestamp}</option>`;
            });

            const params      = new URLSearchParams(window.location.search);
            const selectedRun = params.get("run_id") || data.run_id;
            runSelect.value   = selectedRun;

            if (!params.get("run_id")) {
                params.set("run_id", selectedRun);
                window.history.replaceState(null, "", "?" + params.toString());
            }

            runSelect.onchange = function () {
                params.set("run_id", this.value);
                window.location.search = params.toString();
            };

            if (callback) callback();
        });
}
