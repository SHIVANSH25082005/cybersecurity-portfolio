import sqlite3

DB_PATH = "database/cyberintel.db"


def _connect():
    return sqlite3.connect(DB_PATH)


def get_financial_summary(case_id, limit=20):
    """Return financial intelligence from explicit transactions and UPI clues.

    The current app mostly stores UPI IDs, not full transaction ledgers. This
    service uses real transaction rows when present and falls back to UPI reuse
    analysis so the workspace can still surface useful fraud-finance leads.
    """
    conn = _connect()
    cursor = conn.cursor()

    transactions = []
    try:
        cursor.execute("""
            SELECT id, victim_name, bank_name, account_number, ifsc, upi_id,
                   merchant, wallet, amount, transaction_time, destination
            FROM financial_transactions
            WHERE case_id = ?
            ORDER BY transaction_time DESC, id DESC
            LIMIT ?
        """, (case_id, limit))
        transactions = [
            {
                "id": row[0],
                "victim_name": row[1],
                "bank_name": row[2],
                "account_number": row[3],
                "ifsc": row[4],
                "upi_id": row[5],
                "merchant": row[6],
                "wallet": row[7],
                "amount": row[8] or 0,
                "transaction_time": row[9],
                "destination": row[10],
            }
            for row in cursor.fetchall()
        ]
    except sqlite3.OperationalError:
        pass

    cursor.execute("""
        SELECT upi_id, COUNT(*) AS hits
        FROM complaints
        WHERE case_id = ? AND upi_id IS NOT NULL AND upi_id != ''
        GROUP BY upi_id
        ORDER BY hits DESC
    """, (case_id,))
    case_upis = cursor.fetchall()

    reused_upis = []
    for upi_id, hits in case_upis:
        cursor.execute("""
            SELECT DISTINCT case_id
            FROM complaints
            WHERE upi_id = ? AND case_id != ? AND case_id IS NOT NULL
            ORDER BY case_id
            LIMIT 10
        """, (upi_id, case_id))
        linked_cases = [row[0] for row in cursor.fetchall()]
        if linked_cases:
            reused_upis.append({
                "upi_id": upi_id,
                "case_hits": hits,
                "linked_cases": linked_cases,
            })

    cursor.execute("""
        SELECT upi_id, COUNT(DISTINCT case_id) AS case_count
        FROM complaints
        WHERE upi_id IS NOT NULL AND upi_id != ''
        GROUP BY upi_id
        HAVING COUNT(DISTINCT case_id) > 1
        ORDER BY case_count DESC
        LIMIT 10
    """)
    platform_reuse = [
        {"upi_id": row[0], "case_count": row[1]}
        for row in cursor.fetchall()
    ]

    conn.close()

    total_amount = sum(float(tx["amount"] or 0) for tx in transactions)
    risk_flags = []
    if reused_upis:
        risk_flags.append("UPI reuse across cases detected.")
    if transactions and total_amount >= 100000:
        risk_flags.append("High-value transaction exposure detected.")
    if any(tx["wallet"] for tx in transactions):
        risk_flags.append("Wallet movement appears in transaction data.")
    if any(tx["destination"] for tx in transactions):
        risk_flags.append("Destination account/wallet is recorded.")

    return {
        "transaction_count": len(transactions),
        "total_amount": round(total_amount, 2),
        "transactions": transactions,
        "case_upis": [
            {"upi_id": row[0], "hits": row[1]} for row in case_upis
        ],
        "reused_upis": reused_upis,
        "platform_reuse": platform_reuse,
        "risk_flags": risk_flags,
    }
import re
import sqlite3


DB_PATH = "database/cyberintel.db"

FINANCIAL_ENTITY_TYPES = {
    "UPI", "BankAccount", "Bank Account", "Wallet", "IFSC",
    "Merchant", "Account", "Transaction"
}

UPI_RE = re.compile(r"^[A-Za-z0-9.\-_]{2,256}@[A-Za-z]{2,64}$")
IFSC_RE = re.compile(r"\b[A-Z]{4}0[A-Z0-9]{6}\b", re.IGNORECASE)
ACCOUNT_RE = re.compile(r"\b\d{9,18}\b")


def _connect():
    return sqlite3.connect(DB_PATH)


def _instrument(kind, value, case_id, source, context=""):
    return {
        "kind": kind,
        "value": value,
        "case_id": case_id,
        "source": source,
        "context": context or ""
    }


def _extract_from_text(text, case_id, source):
    instruments = []
    if not text:
        return instruments

    for match in IFSC_RE.findall(text):
        instruments.append(_instrument("IFSC", match.upper(), case_id, source))

    for match in ACCOUNT_RE.findall(text):
        instruments.append(_instrument("Account", match, case_id, source))

    for token in re.split(r"\s|,|;|\(|\)|\[|\]|<|>", text):
        cleaned = token.strip(" .:-")
        if UPI_RE.match(cleaned):
            instruments.append(_instrument("UPI", cleaned, case_id, source))

    return instruments


def collect_financial_instruments(case_id=None):
    """Return financial indicators from the current schema.

    The platform does not yet have transaction tables, so this module uses
    UPI fields, financial entity types, and financial-looking text indicators.
    Future bank/wallet tables can be added here without changing callers.
    """
    conn = _connect()
    cursor = conn.cursor()
    params = []
    where = ""
    if case_id:
        where = "WHERE case_id = ?"
        params.append(case_id)

    instruments = []

    cursor.execute(
        "SELECT case_id, upi_id, complaint_details FROM complaints " + where,
        params
    )
    for row_case_id, upi_id, details in cursor.fetchall():
        if upi_id:
            instruments.append(
                _instrument("UPI", upi_id, row_case_id, "Complaint")
            )
        instruments.extend(
            _extract_from_text(details, row_case_id, "Complaint Details")
        )

    cursor.execute(
        "SELECT case_id, entity_type, entity_value FROM entities " + where,
        params
    )
    for row_case_id, entity_type, entity_value in cursor.fetchall():
        if entity_type in FINANCIAL_ENTITY_TYPES or UPI_RE.match(entity_value or ""):
            instruments.append(
                _instrument(entity_type or "Financial", entity_value,
                            row_case_id, "Entity")
            )

    conn.close()

    seen = set()
    deduped = []
    for item in instruments:
        key = (item["kind"], item["value"], item["case_id"], item["source"])
        if item["value"] and key not in seen:
            seen.add(key)
            deduped.append(item)
    return deduped


def analyze_case_financials(case_id):
    case_instruments = collect_financial_instruments(case_id)
    values = sorted({item["value"] for item in case_instruments if item["value"]})

    if not values:
        return {
            "available": False,
            "message": "No financial indicators found for this case.",
            "instrument_count": 0,
            "unique_instrument_count": 0,
            "reused": [],
            "clusters": [],
            "flow": [],
            "risk_flags": [],
            "summary": "No UPI, bank account, wallet, IFSC or transaction indicators are currently recorded."
        }

    conn = _connect()
    cursor = conn.cursor()

    reused = []
    for value in values:
        cursor.execute("""
            SELECT DISTINCT case_id FROM (
                SELECT case_id FROM complaints WHERE upi_id = ?
                UNION
                SELECT case_id FROM entities WHERE entity_value = ?
            )
            WHERE case_id IS NOT NULL AND case_id != ?
            ORDER BY case_id
        """, (value, value, case_id))
        linked = [row[0] for row in cursor.fetchall()]
        if linked:
            reused.append({
                "value": value,
                "linked_cases": linked,
                "linked_case_count": len(linked)
            })

    cursor.execute("""
        SELECT upi_id, COUNT(DISTINCT case_id) AS cases
        FROM complaints
        WHERE upi_id IS NOT NULL AND upi_id != ''
        GROUP BY upi_id
        HAVING COUNT(DISTINCT case_id) > 1
        ORDER BY cases DESC
        LIMIT 10
    """)
    clusters = [
        {"value": row[0], "case_count": row[1]}
        for row in cursor.fetchall()
    ]
    conn.close()

    flow = []
    for item in case_instruments:
        if item["kind"] == "UPI":
            flow.append({
                "from": "Victim/Complaint",
                "to": item["value"],
                "relation": "reported UPI"
            })
        elif item["kind"] in ("Account", "BankAccount", "Bank Account"):
            flow.append({
                "from": "Complaint/Entity",
                "to": item["value"],
                "relation": "account indicator"
            })
        elif item["kind"] in ("Wallet", "Merchant", "IFSC"):
            flow.append({
                "from": "Complaint/Entity",
                "to": item["value"],
                "relation": item["kind"]
            })

    risk_flags = []
    if reused:
        risk_flags.append("Financial indicator reused across cases.")
    if len(values) >= 3:
        risk_flags.append("Multiple financial instruments require verification.")
    if any(item["kind"] == "IFSC" for item in case_instruments):
        risk_flags.append("IFSC/bank branch indicator found.")

    summary = (
        f"{len(values)} unique financial indicator(s) found; "
        f"{len(reused)} reused across other case(s)."
    )

    return {
        "available": True,
        "message": "",
        "instrument_count": len(case_instruments),
        "unique_instrument_count": len(values),
        "instruments": case_instruments[:25],
        "reused": reused[:20],
        "clusters": clusters,
        "flow": flow[:25],
        "risk_flags": risk_flags,
        "summary": summary
    }
