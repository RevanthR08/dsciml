import sys, os, contextlib, io, json
import pandas as pd
import numpy as np
from datetime import datetime

sys.path.append(os.getcwd())

from log_analyzer.models import IsolationForest
from log_analyzer import preprocessing

IMPOSSIBLE_TRAVEL_MAX_TRANSITIONS = 50

THREAT_METADATA = {
    'Ransomware — Encryption':        {'MitreID': 'T1486', 'Tactic': 'Impact',               'Risk': 10},
    'Ransomware — Anti-Recovery':     {'MitreID': 'T1490', 'Tactic': 'Impact',               'Risk': 10},
    'Malware — Mimikatz':             {'MitreID': 'T1003', 'Tactic': 'Credential Access',    'Risk': 10},
    'Malware — Suspicious Execution': {'MitreID': 'T1204', 'Tactic': 'Execution',            'Risk': 9},
    'Brute Force':                    {'MitreID': 'T1110', 'Tactic': 'Credential Access',    'Risk': 6},
    'Privilege Escalation':           {'MitreID': 'T1078', 'Tactic': 'Privilege Escalation', 'Risk': 9},
    'Suspicious Process Exec':        {'MitreID': 'T1059', 'Tactic': 'Execution',            'Risk': 7},
    'Network Recon':                  {'MitreID': 'T1046', 'Tactic': 'Discovery',            'Risk': 5},
    'Suspicious DNS Query':           {'MitreID': 'T1071', 'Tactic': 'Command & Control',    'Risk': 7},
    'Bluetooth Exfiltration':         {'MitreID': 'T1011', 'Tactic': 'Exfiltration',         'Risk': 9},
    'Log Tampering':                  {'MitreID': 'T1070', 'Tactic': 'Defense Evasion',      'Risk': 10},
    'Service Installation':           {'MitreID': 'T1543', 'Tactic': 'Persistence',          'Risk': 8},
    'Lateral Movement':               {'MitreID': 'T1021', 'Tactic': 'Lateral Movement',     'Risk': 8},
    'Normal':                         {'MitreID': 'None',  'Tactic': 'None',                 'Risk': 0},
}

ADMIN_ACCOUNTS = {'CORP\\Administrator', 'NT AUTHORITY\\SYSTEM'}
GUEST_ACCOUNTS = {'CORP\\Guest'}

LATERAL_MOVEMENT_WHITELIST = {
    'NT AUTHORITY\\SYSTEM',
    'CORP\\Admin_User',
}
LATERAL_MOVEMENT_WINDOW_MIN = 5

SYSTEM_ACCOUNTS = {
    'NT AUTHORITY\\SYSTEM',
    'NT AUTHORITY\\LOCAL SERVICE',
    'NT AUTHORITY\\NETWORK SERVICE',
    'S-1-5-18',
    'S-1-5-19',
    'S-1-5-20',
    '',
}

def classify_vectorized(df):
    """Vectorized classification using the simplified, real-threat-only label set."""
    df['AttackCategory'] = 'Normal'

    eid = pd.to_numeric(df['event ID'], errors='coerce').fillna(-1).astype(int)
    user = df['User'].astype(str).str.lower()

    detail = df.get('detail', pd.Series('', index=df.index)).astype(str).str.lower()
    message = df.get('Message', pd.Series('', index=df.index)).astype(str).str.lower()
    brief = df.get('Brief', pd.Series('', index=df.index)).astype(str).str.lower()

    combined = detail + " " + message + " " + brief

    # -------------------------
    # 🔴 HIGH PRIORITY (Ransomware)
    # -------------------------
    df.loc[combined.str.contains(r'encrypt|\.locked|\.enc', na=False), 'AttackCategory'] = 'Ransomware — Encryption'
    df.loc[combined.str.contains(r'vssadmin|shadow copy|wbadmin', na=False), 'AttackCategory'] = 'Ransomware — Anti-Recovery'

    # -------------------------
    # 🔴 MALWARE
    # -------------------------
    df.loc[combined.str.contains('mimikatz', na=False), 'AttackCategory'] = 'Malware — Mimikatz'
    df.loc[combined.str.contains(r'powershell.*-enc|cmd.exe.*temp', na=False), 'AttackCategory'] = 'Malware — Suspicious Execution'

    # -------------------------
    # 🟠 AUTH ATTACKS
    # -------------------------
    df.loc[eid == 4625, 'AttackCategory'] = 'Brute Force'
    df.loc[(eid == 4624) & (df['User'].isin(['admin', 'CORP\\Administrator'])), 'AttackCategory'] = 'Privilege Escalation'

    # -------------------------
    # 🟡 PROCESS ABUSE
    # -------------------------
    df.loc[(eid == 4688) & 
           combined.str.contains('powershell|cmd.exe', na=False) & 
           (~df['User'].str.contains('system|network service', case=False)), 'AttackCategory'] = 'Suspicious Process Exec'

    # -------------------------
    # 🟡 NETWORK / EXFIL
    # -------------------------
    df.loc[eid == 3, 'AttackCategory'] = 'Network Recon'
    df.loc[eid == 22, 'AttackCategory'] = 'Suspicious DNS Query'
    df.loc[eid == 18, 'AttackCategory'] = 'Bluetooth Exfiltration'

    # -------------------------
    # 🟡 SYSTEM EVENTS
    # -------------------------
    df.loc[eid == 1102, 'AttackCategory'] = 'Log Tampering'
    df.loc[eid == 7045, 'AttackCategory'] = 'Service Installation'

    return df


def detect_bruteforce_success(df, window_minutes=10):
    fails   = df[df['event ID'] == 4625][['logged', 'computer']].copy()
    success = df[df['event ID'] == 4624][['logged', 'computer']].copy()
    if fails.empty or success.empty:
        return set(), set()

    merged_fail = pd.merge_asof(
        fails.sort_values('logged'),
        success.sort_values('logged'),
        on='logged', by='computer',
        direction='forward',
        tolerance=pd.Timedelta(f'{window_minutes}min')
    )
    hits_fail = merged_fail.dropna()
    fail_keys = set(zip(hits_fail['computer'], hits_fail['logged']))

    merged_succ = pd.merge_asof(
        fails.rename(columns={'logged': 'logged_f'}).sort_values('logged_f'),
        success.rename(columns={'logged': 'logged_s'}).sort_values('logged_s'),
        left_on='logged_f', right_on='logged_s',
        by='computer',
        direction='forward',
        tolerance=pd.Timedelta(f'{window_minutes}min')
    )
    hits_succ    = merged_succ.dropna()
    success_keys = set(zip(hits_succ['computer'], hits_succ['logged_s']))

    return fail_keys, success_keys


def detect_lateral_movement(df):
    """
    O(N) optimized detection of lateral movement.
    """
    logons = df[
        (df['event ID'] == 4624) & 
        (~df['User'].isin(SYSTEM_ACCOUNTS))
    ][['logged', 'computer', 'User']].copy()
    
    if logons.empty: return set()

    # Optimized sliding window using vectorized properties where possible
    logons = logons.sort_values(['User', 'logged'])
    lateral_indices = []
    
    # We use a grouped approach but keep logic tight
    for user, grp in logons.groupby('User'):
        if user in LATERAL_MOVEMENT_WHITELIST: continue
        
        times = grp['logged'].values
        comps = grp['computer'].values
        indices = grp.index.values
        
        n = len(times)
        if n < 2: continue
        
        left = 0
        active_comps = {}
        
        for right in range(n):
            c_right = comps[right]
            active_comps[c_right] = active_comps.get(c_right, 0) + 1
            
            while times[right] - times[left] > np.timedelta64(LATERAL_MOVEMENT_WINDOW_MIN, 'm'):
                c_left = comps[left]
                active_comps[c_left] -= 1
                if active_comps[c_left] == 0: del active_comps[c_left]
                left += 1
            
            if len(active_comps) >= 2:
                lateral_indices.append(indices[right])

    return set(lateral_indices)


class TerminalCapture:
    def __init__(self):
        self.buffer = io.StringIO()
        self.stdout = sys.stdout

    def write(self, message):
        try:
            self.stdout.write(message)
        except UnicodeEncodeError:
            self.stdout.write(message.encode('ascii', 'replace').decode('ascii'))
        self.buffer.write(message)

    def flush(self):
        self.stdout.flush()
        self.buffer.flush()

    def get_output(self):
        return self.buffer.getvalue()


def run_forensic_analysis(file_bytes: bytes = None, filename: str = None, return_dict=True):
    """
    Execute forensic analysis on file bytes (in-memory, zero local storage).
    Supports CSV and EVTX formats.
    
    Args:
        file_bytes: Raw file content as bytes (replaces OS environ)
        filename: Original filename (to detect format: .csv or .evtx)
        return_dict: If True, returns dict; if False, writes to disk (backward compat)
    
    Returns:
        dict with analysis results (if return_dict=True), or path (if writing to disk)
    """
    # Backward compat: fall back to environment variable if file_bytes not provided
    if file_bytes is None:
        log_file = None
        if len(sys.argv) > 1 and os.path.isfile(sys.argv[1]):
            log_file = sys.argv[1]
        else:
            log_file = os.getenv('SOC_LOG_FILE')
        
        if not log_file:
            return {"error": "No log file provided. Pass file_bytes parameter or set SOC_LOG_FILE environment variable."}
        
        # Fall back to reading from disk
        with open(log_file, 'rb') as f:
            file_bytes = f.read()
        filename = os.path.basename(log_file)
    
    W = 82
    capture = TerminalCapture()

    with contextlib.redirect_stdout(capture):
        print("\n" + "="*W)
        print("  🛡️  SOC DETECTION SYSTEM  v3.6  —  MESSAGE-FREE EVTX EDITION")
        print("="*W)
        print(f"  📁 File : {filename}")
        print(f"  💾 Mode : In-Memory Processing (zero disk storage)")

        # ⚡ Detect format from filename
        is_evtx = filename.lower().endswith('.evtx')
        
        try:
            if is_evtx:
                # For EVTX: Temporarily write to disk, parse, then delete immediately
                import tempfile
                temp_evtx = tempfile.NamedTemporaryFile(suffix='.evtx', delete=False)
                try:
                    temp_evtx.write(file_bytes)
                    temp_evtx.close()
                    
                    # Parse EVTX to DataFrame
                    from evtx_parser import parse_evtx_file
                    df = parse_evtx_file(temp_evtx.name)
                finally:
                    # Delete temp EVTX immediately (very brief lifetime)
                    os.unlink(temp_evtx.name)
            else:
                # For CSV: Use StringIO (pure in-memory, no disk)
                file_text = file_bytes.decode('utf-8', errors='ignore')
                first_line = file_text.split('\n')[0] if file_text else ''
                sep = '|' if '|' in first_line else ','
                
                csv_buffer = io.StringIO(file_text)
                try:
                    df = pd.read_csv(csv_buffer, sep=sep, low_memory=False)
                except Exception:
                    csv_buffer.seek(0)
                    df = pd.read_csv(csv_buffer, sep=sep, quoting=3, low_memory=False)
        except Exception as e:
            print(f"  ❌ Cannot load: {e}")
            return {"error": f"Failed to parse file: {e}"}
        
        print(f"  📊 Logs : {len(df):,}")
        if len(df) == 0:
            print("  ⚠️ Warning: File is empty or could not be parsed correctly.")
            return
        print("="*W)

        print(f"  📊 Columns : {df.columns.tolist()}")
        df.columns = [str(c).strip().lower() for c in df.columns]
        
        # ⚡ Remove duplicate columns (keep first occurrence)
        # This handles case like both 'opcode' and 'Opcode' becoming 'opcode'
        df = df.loc[:, ~df.columns.duplicated(keep='first')]
        
        # ⚡ Mapping logic: find which CSV column matches our internal requirement
        COL_MAP = {
            'logged': next(
                (c for c in df.columns if c in ['logged', 'timegenerated', 'systemtime', 'timestamp']),
                None,
            ),
            'event_id': next(
                (c for c in df.columns if c in ['event_id', 'event id', 'eventid', 'event_type']),
                None,
            ),
            'user': next(
                (c for c in df.columns if c in ['user', 'userid', 'accountname']),
                None,
            ),
            'opcode': next((c for c in df.columns if c in ['opcode', 'app_name']), None),
            'opcode_display': next(
                (c for c in df.columns if c in ['opcodedisplayname', 'opcode display name', 'opcodedisplay']),
                None,
            ),
            'task_category': next(
                (
                    c
                    for c in df.columns
                    if c in ['task_category', 'task category', 'taskcategory', 'task', 'event_type']
                ),
                None,
            ),
            'log_name': next(
                (c for c in df.columns if c in ['logname', 'log name', 'channel']),
                None,
            ),
            'account_domain': next(
                (c for c in df.columns if c in ['accountdomain', 'account domain']),
                None,
            ),
            'computer': next(
                (c for c in df.columns if c in ['computer', 'device_id', 'machinename']),
                None,
            ),
            'source': next(
                (c for c in df.columns if c in ['source', 'provider', 'name', 'providername']),
                None,
            ),
            'process_id': next(
                (
                    c
                    for c in df.columns
                    if c in ['processid', 'process_id', 'pid', 'execution processid']
                ),
                None,
            ),
        }
        
        optional = ('source', 'opcode_display', 'log_name', 'account_domain')
        missing = [k for k, v in COL_MAP.items() if v is None and k not in optional]
        if missing:
            print(f"  ❌ Missing columns: {missing}  |  Found: {df.columns.tolist()}")
            return

        # ⚡ Map to the legacy names used by detection functions
        def _get_col(key):
            col_name = COL_MAP.get(key)
            if not col_name: return pd.Series('', index=df.index)
            val = df[col_name]
            if isinstance(val, pd.DataFrame):
                # If duplicates exist (e.g. 'opcode' vs 'Opcode'), pick the last one
                # The user noted the first one can be non-numeric 'info' string.
                return val.iloc[:, -1]
            return val

        df['logged'] = _get_col('logged')
        df['event ID'] = _get_col('event_id')
        df['User'] = _get_col('user')
        df['Opcode'] = _get_col('opcode')
        if COL_MAP['opcode_display']:
            df['OpcodeDisplay'] = _get_col('opcode_display')
        else:
            df['OpcodeDisplay'] = df['Opcode']
        df['task Category'] = _get_col('task_category')
        df['LogName'] = _get_col('log_name') if COL_MAP['log_name'] else pd.Series('', index=df.index)
        df['AccountDomain'] = _get_col('account_domain') if COL_MAP['account_domain'] else pd.Series('', index=df.index)
        df['computer'] = _get_col('computer')
        if COL_MAP['source']:
            df['source'] = _get_col('source')
        df['process_id'] = _get_col('process_id')
        
        print(f"  ✅ Mapped Columns: {df.columns.tolist()}")

        # ⚡ OPTIMIZATION: High-speed date parsing
        if 'logged' in df.columns:
            # Try ISO8601 first (Fastest for modern logs)
            t_try = pd.to_datetime(df['logged'], format='ISO8601', errors='coerce')
            
            # Try common CSV export format
            if t_try.isna().sum() > len(df) * 0.5:
                t_try = pd.to_datetime(df['logged'], format='%m/%d/%Y %I:%M:%S %p', errors='coerce')
            
            # Try YYYY-MM-DD HH:MM:SS
            if t_try.isna().sum() > len(df) * 0.5:
                t_try = pd.to_datetime(df['logged'], format='%Y-%m-%d %H:%M:%S', errors='coerce')

            # Fallback to slow inference only if necessary
            if t_try.isna().sum() > len(df) * 0.5:
                t_try = pd.to_datetime(df['logged'], errors='coerce')

            df['logged'] = t_try
        df = df.dropna(subset=['logged'])

        if len(df) == 0:
            print("  ⚠️ Warning: No valid timestamps found. Detection could not proceed.")
            return

        for col in ('Opcode', 'OpcodeDisplay', 'task Category', 'LogName', 'AccountDomain', 'source', 'User'):
            df[col] = df.get(col, pd.Series('', index=df.index)).fillna('')

        u = df['User'].astype(str)
        empty_ad = df['AccountDomain'].astype(str).str.len() == 0
        df.loc[empty_ad, 'AccountDomain'] = np.where(
            u.str.contains('\\', regex=False),
            u.str.split('\\').str[0],
            '',
        )

        print("  🔍 Running temporal correlation passes...")
        bf_fail_keys, bf_success_keys = detect_bruteforce_success(df)
        lateral_indices = detect_lateral_movement(df)

        print("  🔠 Vectorizing classifications...")
        df = classify_vectorized(df)

        # Lateral Movement overlay (from temporal correlation)
        df.loc[df.index.isin(lateral_indices), 'AttackCategory'] = 'Lateral Movement'

        df['MitreID']    = df['AttackCategory'].map(lambda x: THREAT_METADATA.get(x, {}).get('MitreID',   '?'))
        df['Tactic']     = df['AttackCategory'].map(lambda x: THREAT_METADATA.get(x, {}).get('Tactic',    '?'))
        df['RiskScore']  = df['AttackCategory'].map(lambda x: THREAT_METADATA.get(x, {}).get('Risk',       0))
        df['TimeBucket'] = df['logged'].dt.floor('1min')

        summary = df['AttackCategory'].value_counts()

        print(f"\n{'─'*W}")
        print("  🚨 RULE-BASED DETECTION  (structural fields only — no Message column)")
        print(f"{'─'*W}")
        print(f"  {'Attack Category':<30} {'Tactic':<24} {'MITRE':<8} {'Risk':>4}  {'Count':>8}")
        print(f"{'─'*W}")

        total_suspicious = 0
        total_risk_score = 0

        for cat, count in summary.items():
            if cat == 'Normal' or count == 0:
                continue
            meta = THREAT_METADATA.get(cat, {'MitreID': '?', 'Tactic': '?', 'Risk': 0})
            total_suspicious += count
            total_risk_score += meta['Risk'] * count
            print(f"  {cat:<30} {meta['Tactic']:<24} {meta['MitreID']:<8} {meta['Risk']:>4}  {count:>8,}")

        active_rule_count  = len([c for c in summary.index if c != 'Normal' and summary[c] > 0])
        total_logs         = len(df)
        threat_density     = round(total_risk_score / (total_logs / 1000), 2) if total_logs > 0 else 0
        normalized_density = round(threat_density / active_rule_count, 2)     if active_rule_count > 0 else 0

        print(f"{'─'*W}")
        print(f"  🔴 Total Threats         : {total_suspicious:,}")
        print(f"  🟢 Normal Activity       : {summary.get('Normal', 0):,}")
        print(f"  🔥 Cumulative Risk Score : {total_risk_score:,}")
        print(f"  📊 Threat Density        : {threat_density:,} risk-pts / 1,000 logs")
        print(f"  📐 Normalized Density    : {normalized_density} risk-pts / 1,000 logs / rule")
        print(f"  📋 Active Rule Count     : {active_rule_count}")

        print(f"\n{'='*W}")
        print("  🤖 ML VALIDATION  (Isolation Forest — behavioral sequences)")
        print(f"{'='*W}")

        anomaly_count        = 0
        rule_flagged_buckets = set()
        agreement_rate       = 0

        if len(df) > 0:
            # ⚡ OPTIMIZATION: Sample the ML pipeline if data is too massive (>50k rows)
            ml_df = df.copy()
            if len(df) > 50000:
                print(f"  ⚡ Massive dataset detected. Sampling 50,000 rows for ML speed...")
                ml_df = df.sample(50000, random_state=42).sort_values('logged')

            # 🧠 Behavioral Enrichment (Pure Features): Include system-level telemetry
            # We skip 'RiskToken' to let the ML find anomalies the rules might miss.
            def _tok_part(s):
                return s.astype(str).str.replace(' ', '_', regex=False)

            ml_df['EventToken'] = (
                ml_df['event ID'].astype(str) + '_' +
                _tok_part(ml_df['task Category']) + '_' +
                _tok_part(ml_df['OpcodeDisplay']) + '_' +
                _tok_part(ml_df['LogName']) + '_' +
                _tok_part(ml_df['AccountDomain'])
            )
            grouped     = ml_df.groupby(['computer', 'TimeBucket'])
            X_seq       = [g['EventToken'].tolist() for _, g in grouped]
            bucket_keys = [k for k, _ in grouped]

            if X_seq:
                try:
                    with contextlib.redirect_stdout(io.StringIO()):
                        fe    = preprocessing.FeatureExtractor()
                        x_mat = fe.fit_transform(np.array(X_seq, dtype=object),
                                                 term_weighting='binary', normalization='zero-mean')
                        if x_mat.shape[0] > 0:
                            # ⚡ Optimization: adjust contamination to 0.1 for better behavioral detection
                            model  = IsolationForest(contamination=0.1, random_state=42)
                            model.fit(x_mat)
                            y_pred = model.predict(x_mat)
                            anomaly_count      = int(np.sum(y_pred == 1))
                            ml_flagged_buckets = {bucket_keys[i] for i, flag in enumerate(y_pred) if flag == 1}

                    # FASTER: using zip for membership test instead of apply()
                    rule_flagged_df = df[df['AttackCategory'] != 'Normal']
                    rule_flagged_buckets = set(zip(rule_flagged_df['computer'], rule_flagged_df['TimeBucket']))
                    overlap        = rule_flagged_buckets & ml_flagged_buckets
                    agreement_rate = round(len(overlap) / max(len(rule_flagged_buckets), 1) * 100, 1)

                    print(f"  ✅ ML flagged         : {anomaly_count:,} anomalous 1-min windows")
                    print(f"  📏 Rule-flagged windows: {len(rule_flagged_buckets):,}")
                    print(f"  🤝 Rule-ML Agreement  : {agreement_rate}%")
                except Exception as e:
                    print(f"  ⚠️ ML Validation failed: {e}")
            else:
                print("  ⚠️ Skipping ML Validation: No sequences found.")
        else:
            print("  ⚠️ Skipping ML Validation: No data available.")

        if agreement_rate == 0:
            pass
        elif agreement_rate >= 70:
            print("     → High agreement: rules and ML are catching the same behaviour")
        elif agreement_rate >= 40:
            print("     → Moderate agreement: ML is finding patterns rules miss (investigate)")
        else:
            print("     → Low agreement: rules and ML diverge — potential false-positive issue")

        print(f"\n{'='*W}")
        print("  ⏱️  ATTACK TIMELINE  (highest-risk event per minute)")
        print(f"{'='*W}")

        anomalous_df = df[df['AttackCategory'] != 'Normal'].sort_values('logged')

        timeline_df = (
            anomalous_df
            .assign(ts=anomalous_df['logged'].dt.strftime('%Y-%m-%d %H:%M'))
            .sort_values(['ts', 'RiskScore'], ascending=[True, False])
            .drop_duplicates(subset=['ts'])
        )

        shown = 0
        for _, row in timeline_df.iterrows():
            risk  = row['RiskScore']
            bar   = '█' * risk + '░' * (10 - risk)
            uname = row['User'].split('\\')[-1] if '\\' in str(row['User']) else str(row['User'])
            print(f"  [{row['ts']}]  {row['AttackCategory']:<28}  {bar} R{risk:<2}  "
                  f"🖥 {row['computer']:<16}  👤 {uname}")
            shown += 1
            if shown >= 20:
                remaining = len(timeline_df) - shown
                print(f"  ... ({remaining:,} more minutes — see JSON for full timeline)")
                break

        if shown == 0:
            print("  No timestamped threats found.")

        print(f"\n{'='*W}")
        print("  🔗 ATTACK CHAIN DETECTION  (per-host kill-chain matcher)")
        print(f"{'='*W}")

        KILL_CHAIN = [
            'Phishing — Anomalous Flow',
            'DNS Reconnaissance',
            'Brute Force',
            'Brute Force — Succeeded',
            'Service Installation',
            'Service Failure',
            'Privilege Escalation',
            'Lateral Movement',
            'Suspicious Process Exec',
            'Malware — Suspicious Execution',
            'Suspicious DNS Query',
            'Ransomware — Encryption',
            'Ransomware — Anti-Recovery',
            'Bluetooth Exfiltration',
            'Insider Theft',
            'Log Tampering',
        ]

        chain_found  = False
        chains_found = []

        for computer, comp_df in anomalous_df.groupby('computer'):
            comp_df = comp_df.sort_values('logged')
            events  = comp_df[['logged', 'AttackCategory']].to_dict('records')
            chain   = []

            for idx, evt in enumerate(events):
                if not chain:
                    if evt['AttackCategory'] in KILL_CHAIN:
                        chain.append(evt)
                else:
                    dt  = (evt['logged'] - chain[-1]['logged']).total_seconds() / 60
                    cat = evt['AttackCategory']
                    if (cat in KILL_CHAIN and
                            KILL_CHAIN.index(cat) >= KILL_CHAIN.index(chain[-1]['AttackCategory']) and
                            dt <= 120 and
                            cat != chain[-1]['AttackCategory']):
                        chain.append(evt)

                is_last     = idx == len(events) - 1
                next_not_kc = (not is_last and
                               events[idx + 1]['AttackCategory'] not in KILL_CHAIN)

                if len(chain) >= 2 and (is_last or next_not_kc):
                    stages = ' → '.join(
                        f"[{e['logged'].strftime('%H:%M')}] {e['AttackCategory']}"
                        for e in chain
                    )
                    print(f"  🚨 CHAIN on {computer}:")
                    print(f"     {stages}")
                    chains_found.append({'computer': computer, 'chain': stages})
                    chain_found = True
                    chain = []

        if not chain_found:
            print("  No multi-stage chains detected.")

        print(f"\n{'='*W}")
        print("  🌍 IMPOSSIBLE TRAVEL  (same user, different host, ≤5 min)")
        print(f"{'='*W}")
        print("  NOTE: Proxy/NAT false positives possible — whitelist known jump boxes\n")

        travel_found   = False
        travel_records = []

        any_activity = (
            df[~df['User'].isin(SYSTEM_ACCOUNTS)]
            [['logged', 'computer', 'User', 'TimeBucket']]
            .drop_duplicates(subset=['User', 'computer', 'TimeBucket'])
            [['logged', 'computer', 'User']]
            .sort_values('logged')
        )

        for user, grp in any_activity.groupby('User'):
            if user in LATERAL_MOVEMENT_WHITELIST:
                continue
            grp = grp.sort_values('logged').reset_index(drop=True)

            travel_pairs = []
            for i in range(len(grp) - 1):
                dt = (grp.loc[i + 1, 'logged'] - grp.loc[i, 'logged']).total_seconds() / 60
                if grp.loc[i, 'computer'] != grp.loc[i + 1, 'computer'] and dt <= 5:
                    travel_pairs.append({
                        'host_a':  grp.loc[i,     'computer'],
                        'time_a':  grp.loc[i,     'logged'],
                        'host_b':  grp.loc[i + 1, 'computer'],
                        'time_b':  grp.loc[i + 1, 'logged'],
                        'gap_min': round(dt, 1),
                    })

            if not travel_pairs:
                continue

            hosts = sorted({p for pair in travel_pairs for p in [pair['host_a'], pair['host_b']]})
            first = travel_pairs[0]

            if len(travel_pairs) > IMPOSSIBLE_TRAVEL_MAX_TRANSITIONS:
                print(f"  ⚠️  PERSISTENT MULTI-HOST SESSION — {user}")
                print(f"     {len(travel_pairs):,} transitions across: {', '.join(hosts)}")
                print(f"     First seen : [{first['time_a'].strftime('%H:%M:%S')}] {first['host_a']}")
                print(f"                  [{first['time_b'].strftime('%H:%M:%S')}] {first['host_b']}  ({first['gap_min']} min apart)")
                print(f"     Action     : review account — add to LATERAL_MOVEMENT_WHITELIST if expected\n")
            else:
                print(f"  🚨 IMPOSSIBLE TRAVEL — {user}")
                print(f"     First seen : [{first['time_a'].strftime('%H:%M:%S')}] {first['host_a']}")
                print(f"                  [{first['time_b'].strftime('%H:%M:%S')}] {first['host_b']}  ({first['gap_min']} min apart)")
                print(f"     Hosts      : {', '.join(hosts)}")
                print(f"     Events     : {len(travel_pairs)} impossible transitions detected\n")

            travel_found = True
            for pair in travel_pairs:
                travel_records.append({
                    'user':    user,
                    'host_a':  pair['host_a'],
                    'time_a':  str(pair['time_a']),
                    'host_b':  pair['host_b'],
                    'time_b':  str(pair['time_b']),
                    'gap_min': pair['gap_min'],
                })

        if not travel_found:
            print("  No impossible travel detected.")

        terminal_summary = capture.get_output()

        export = {
            '_terminal_summary': terminal_summary,
            '_meta': {
                'generated_at':       datetime.now().isoformat(),
                'log_platform':       'windows',
                'total_logs':         len(df),
                'total_threats':      total_suspicious,
                'risk_score':         total_risk_score,
                'threat_density':     threat_density,
                'normalized_density': normalized_density,
                'active_rules':       active_rule_count,
                'rule_ml_agreement':  f"{agreement_rate}%",
            },
            '_attack_chains':     chains_found,
            '_impossible_travel': travel_records,
        }

        for cat, grp in anomalous_df.groupby('AttackCategory'):
            meta = THREAT_METADATA.get(cat, {})
            grp  = grp.copy()
            grp['logged'] = grp['logged'].astype(str)
            export[cat] = {
                'mitre_id':   meta.get('MitreID', '?'),
                'tactic':     meta.get('Tactic',  '?'),
                'risk_score': meta.get('Risk', 0),
                'count':      len(grp),
                'events':     grp[['logged', 'event ID', 'User', 'computer',
                                   'task Category', 'MitreID', 'Tactic', 'RiskScore']]
                                  .to_dict(orient='records'),
            }

        # Add Normal activity logs at the end
        normal_df = df[df['AttackCategory'] == 'Normal'].copy()
        if len(normal_df) > 0:
            normal_df['logged'] = normal_df['logged'].astype(str)
            meta = THREAT_METADATA.get('Normal', {})
            export['Normal'] = {
                'mitre_id':   meta.get('MitreID', '?'),
                'tactic':     meta.get('Tactic',  '?'),
                'risk_score': meta.get('Risk', 0),
                'count':      len(normal_df),
                'events':     normal_df[['logged', 'event ID', 'User', 'computer',
                                         'task Category', 'MitreID', 'Tactic', 'RiskScore']]
                                    .to_dict(orient='records'),
            }

        if return_dict:
            # Return data in-memory (new approach)
            print(f"\n{'='*W}")
            print(f"  💾 ANALYSIS COMPLETE (in-memory, no local storage)")
            print(f"{'='*W}\n")
            return export
        else:
            # Write to disk (backward compat)
            out_dir  = 'detected_anomalies'
            os.makedirs(out_dir, exist_ok=True)
            ts_str   = datetime.now().strftime('%Y%m%d_%H%M%S')
            out_path = os.path.join(out_dir, f'anomalous_logs_{ts_str}.json')

            with open(out_path, 'w', encoding='utf-8') as f:
                json.dump(export, f, indent=4)

            print(f"\n{'='*W}")
            print(f"  💾 EXPORT → {out_path}")
            print(f"{'='*W}\n")
            return out_path


if __name__ == '__main__':
    run_forensic_analysis()
