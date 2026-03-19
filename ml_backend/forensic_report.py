import sys, os, contextlib, io, json
import pandas as pd
import numpy as np
from datetime import datetime

sys.path.append(os.getcwd())

from log_analyzer.models import IsolationForest
from log_analyzer import preprocessing

# Check for command-line argument first, then environment variable, else use default
if len(sys.argv) > 1 and os.path.isfile(sys.argv[1]):
    log_file = sys.argv[1]
else:
    log_file = os.getenv('SOC_LOG_FILE')

IMPOSSIBLE_TRAVEL_MAX_TRANSITIONS = 50

THREAT_METADATA = {
    'Brute Force':              {'MitreID': 'T1110', 'Tactic': 'Credential Access',    'Risk': 6},
    'Brute Force — Succeeded':  {'MitreID': 'T1110', 'Tactic': 'Credential Access',    'Risk': 9},
    'Privilege Escalation':     {'MitreID': 'T1078', 'Tactic': 'Privilege Escalation', 'Risk': 9},
    'Suspicious Process Exec':  {'MitreID': 'T1059', 'Tactic': 'Execution',            'Risk': 7},
    'Malware — Persistence':    {'MitreID': 'T1547', 'Tactic': 'Persistence',          'Risk': 8},
    'Malware — Mimikatz':       {'MitreID': 'T1003', 'Tactic': 'Credential Access',    'Risk': 10},
    'Malware — Suspicious Execution': {'MitreID': 'T1204', 'Tactic': 'Execution',        'Risk': 9},
    'Ransomware — Encryption':  {'MitreID': 'T1486', 'Tactic': 'Impact',               'Risk': 10},
    'Ransomware — Anti-Recovery':{'MitreID': 'T1490', 'Tactic': 'Impact',               'Risk': 10},
    'Log Tampering':            {'MitreID': 'T1070', 'Tactic': 'Defense Evasion',      'Risk': 10},
    'Lateral Movement':         {'MitreID': 'T1021', 'Tactic': 'Lateral Movement',     'Risk': 8},
    'Phishing — Anomalous Flow': {'MitreID': 'T1566', 'Tactic': 'Initial Access',       'Risk': 7},
    'Suspicious DNS Query':     {'MitreID': 'T1071', 'Tactic': 'Command & Control',    'Risk': 7},
    'Guest Account Activity':   {'MitreID': 'T1078', 'Tactic': 'Initial Access',       'Risk': 8},
    'Network Recon':            {'MitreID': 'T1046', 'Tactic': 'Discovery',            'Risk': 5},
    'Service Installation':     {'MitreID': 'T1543', 'Tactic': 'Persistence',          'Risk': 8},
    'Service Failure':          {'MitreID': 'T1489', 'Tactic': 'Impact',               'Risk': 6},
    'DNS Reconnaissance':       {'MitreID': 'T1590', 'Tactic': 'Reconnaissance',       'Risk': 5},
    'Bluetooth Exfiltration':   {'MitreID': 'T1011', 'Tactic': 'Exfiltration',         'Risk': 9},
    'Insider Theft':            {'MitreID': 'T1052', 'Tactic': 'Exfiltration',         'Risk': 9},
    'Normal':                   {'MitreID': 'None',  'Tactic': 'None',                 'Risk': 0},
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

# 🛠️ ADVANCED SIGNATURE PATTERNS
RANSOMWARE_EXT = ('.locked', '.encrypted', '.wncry', '.crypt', '.locky', '.cerber', '.zepto', '.aesir', '.thor', '.zzzzz', '.aes', '.enc', '.darkside', '.conti', '.revil')
MALWARE_PROCESSES = ('mimikatz', 'psexec', 'nc.exe', 'cobaltstrike', 'metasploit', 'bloodhound', 'sharphound', 'remcos', 'nanocore', 'njrat', 'anydesk', 'teamviewer')
PERSISTENCE_CMD = ('reg add', 'schtasks', 'wmic', 'sc create', 'startup', 'currentversion\\run')
PHISHING_INDICATORS = ('bit.ly', 'tinyurl.com', 'login-verification', 'secure-update', 'account-blocked', 'invoice', 'payment', 'urgent')

def classify_row(eid, user, opcode, task_cat, source, detail=''):
    eid      = int(eid) if str(eid).isdigit() else -1
    user     = str(user).strip()
    opcode   = str(opcode).strip().lower()
    task_cat = str(task_cat).strip().lower()
    source   = str(source).strip().lower()
    msg      = str(detail).lower()

    # 🚨 RANSOMWARE SIGNATURES
    if any(ext in msg for ext in RANSOMWARE_EXT) or 'encrypt' in msg:
        if 'process' in msg or 'file' in msg:
            return 'Ransomware — Encryption'
    if 'vssadmin' in msg and 'delete' in msg and 'shadows' in msg:
        return 'Ransomware — Anti-Recovery'
    if 'wbadmin' in msg and 'delete' in msg:
        return 'Ransomware — Anti-Recovery'
    if 'bcdedit' in msg and 'recoveryenabled' in msg and 'no' in msg:
        return 'Ransomware — Anti-Recovery'

    # 🚨 MALWARE SIGNATURES
    if any(p in msg for p in MALWARE_PROCESSES):
        return 'Malware — Mimikatz' if 'mimikatz' in msg else 'Suspicious Process Exec'
    if eid == 1 and ('powershell' in msg or 'cmd.exe' in msg) and ('-enc' in msg or '-encodedcommand' in msg or 'bypass' in msg):
        return 'Malware — Persistence'
    if any(cmd in msg for cmd in PERSISTENCE_CMD):
        return 'Malware — Persistence'
    if 'temp' in msg and ('.exe' in msg or '.scr' in msg or '.vbs' in msg) and eid == 1:
        return 'Malware — Suspicious Execution'

    # 🚨 PHISHING SIGNATURES
    if any(ind in msg for ind in PHISHING_INDICATORS):
        if 'http' in msg or 'click' in msg:
            return 'Phishing — Anomalous Flow'
    if eid == 4624 and 'external' in msg:
        return 'Phishing — Anomalous Flow'
    
    # 🚨 LEGACY LOGIC
    if eid == 1102:
        return 'Log Tampering'
    if eid == 4625:
        return 'Brute Force'
    if eid == 4624 and user in ADMIN_ACCOUNTS:
        return 'Privilege Escalation'
    if user in GUEST_ACCOUNTS and eid in (4624, 3, 1):
        return 'Guest Account Activity'
    if eid == 1 and 'process create' in task_cat and user not in {'NT AUTHORITY\\SYSTEM'}:
        return 'Suspicious Process Exec'
    if eid == 22:
        return 'Suspicious DNS Query'
    if eid == 1014:
        return 'DNS Reconnaissance'
    if eid == 3 and user in ADMIN_ACCOUNTS | GUEST_ACCOUNTS:
        return 'Network Recon'
    if eid == 7045:
        return 'Service Installation'
    if eid == 7000:
        return 'Service Failure'
    if eid == 18:
        return 'Bluetooth Exfiltration'
    if eid == 24635:
        return 'Insider Theft'
    
    # 🚨 PHISHING / ANOMALY (Heuristic)
    if eid == 4624 and 'external' in msg:
        return 'Phishing — Anomalous Flow'
    
    return 'Normal'


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


def run_forensic_analysis():
    W = 82
    capture = TerminalCapture()

    with contextlib.redirect_stdout(capture):
        print("\n" + "="*W)
        print("  🛡️  SOC DETECTION SYSTEM  v3.6  —  MESSAGE-FREE EVTX EDITION")
        print("="*W)
        print(f"  📁 File : {log_file}")

        try:
            with open(log_file, 'r', encoding='utf-8', errors='ignore') as f:
                first_line = f.readline()
            sep = '|' if '|' in first_line else ','

            try:
                df = pd.read_csv(log_file, sep=sep, low_memory=False)
            except Exception:
                df = pd.read_csv(log_file, sep=sep, quoting=3, low_memory=False)
        except Exception as e:
            print(f"  ❌ Cannot load: {e}")
            return

        print(f"  📊 Logs : {len(df):,}")
        if len(df) == 0:
            print("  ⚠️ Warning: File is empty or could not be parsed correctly.")
            return
        print("="*W)

        print(f"  📊 Columns : {df.columns.tolist()}")
        df.columns = [str(c).strip().lower() for c in df.columns]
        
        # ⚡ Mapping logic: find which CSV column matches our internal requirement
        COL_MAP = {
            'logged':        next((c for c in df.columns if c in ['logged', 'timegenerated', 'systemtime', 'timestamp']), None),
            'event id':      next((c for c in df.columns if c in ['event id', 'eventid', 'event_type']),                   None),
            'user':          next((c for c in df.columns if c in ['user', 'userid']),                        None),
            'opcode':        next((c for c in df.columns if c in ['opcode', 'app_name']),                                   None),
            'task category': next((c for c in df.columns if c in ['task category', 'taskcategory', 'task', 'event_type']), None),
            'computer':      next((c for c in df.columns if c in ['computer', 'device_id']),                                 None),
            'source':        next((c for c in df.columns if c in ['source', 'provider', 'name']),            None),
        }
        
        missing = [k for k, v in COL_MAP.items() if v is None and k not in ('source',)]
        if missing:
            print(f"  ❌ Missing columns: {missing}  |  Found: {df.columns.tolist()}")
            return

        # ⚡ Map to the legacy names used by detection functions
        df['logged'] = df[COL_MAP['logged']]
        df['event ID'] = df[COL_MAP['event id']]
        df['User'] = df[COL_MAP['user']]
        df['Opcode'] = df[COL_MAP['opcode']]
        df['task Category'] = df[COL_MAP['task category']]
        df['computer'] = df[COL_MAP['computer']]
        if COL_MAP['source']:
            df['source'] = df[COL_MAP['source']]
        
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

        for col in ('Opcode', 'task Category', 'source', 'User'):
            df[col] = df.get(col, pd.Series('', index=df.index)).fillna('')

        print("  🔍 Running temporal correlation passes...")
        bf_fail_keys, bf_success_keys = detect_bruteforce_success(df)
        lateral_indices = detect_lateral_movement(df)

        print("  🔠 Vectorizing classifications...")
        # 🟢 Baseline categorization
        df['AttackCategory'] = 'Normal'

        # Convert columns to simple types for fast comparison
        eid_series = pd.to_numeric(df['event ID'], errors='coerce').fillna(-1).astype(int)
        user_series = df['User'].astype(str).str.strip()
        task_cat_series = df['task Category'].astype(str).str.strip().str.lower()
        
        # ⚡ Applying rules using vectorized masks (Fastest way in Pandas)
        msg_series = df['detail'].astype(str).str.lower() if 'detail' in df.columns else pd.Series('', index=df.index)
        
        # Ransomware Vectorized
        for ext in RANSOMWARE_EXT:
            df.loc[msg_series.str.contains(ext, na=False), 'AttackCategory'] = 'Ransomware — Encryption'
        df.loc[msg_series.str.contains('vssadmin', na=False) & msg_series.str.contains('delete', na=False), 'AttackCategory'] = 'Ransomware — Anti-Recovery'
        
        # Malware Vectorized
        for p in MALWARE_PROCESSES:
            df.loc[msg_series.str.contains(p, na=False), 'AttackCategory'] = 'Malware — Mimikatz' if p == 'mimikatz' else 'Suspicious Process Exec'
            
        df.loc[eid_series == 1102, 'AttackCategory'] = 'Log Tampering'
        df.loc[eid_series == 4625, 'AttackCategory'] = 'Brute Force'
        df.loc[(eid_series == 4624) & (user_series.isin(ADMIN_ACCOUNTS)), 'AttackCategory'] = 'Privilege Escalation'
        df.loc[(user_series.isin(GUEST_ACCOUNTS)) & (eid_series.isin([4624, 3, 1])), 'AttackCategory'] = 'Guest Account Activity'
        df.loc[(eid_series == 1) & (task_cat_series.str.contains('process create', na=False)) & (~user_series.str.contains('NT AUTHORITY', na=False)), 'AttackCategory'] = 'Suspicious Process Exec'
        df.loc[eid_series == 22, 'AttackCategory'] = 'Suspicious DNS Query'
        df.loc[eid_series == 1014, 'AttackCategory'] = 'DNS Reconnaissance'
        df.loc[(eid_series == 3) & (user_series.isin(ADMIN_ACCOUNTS | GUEST_ACCOUNTS)), 'AttackCategory'] = 'Network Recon'
        df.loc[eid_series == 7045, 'AttackCategory'] = 'Service Installation'
        df.loc[eid_series == 7000, 'AttackCategory'] = 'Service Failure'
        df.loc[eid_series == 18, 'AttackCategory'] = 'Bluetooth Exfiltration'
        df.loc[eid_series == 24635, 'AttackCategory'] = 'Insider Theft'

        # Brute Force success override
        # Use vectorized set-lookup for high-speed correlation
        if bf_fail_keys or bf_success_keys:
            df_comp = df['computer'].values
            df_logged = df['logged'].values
            
            # Vectorized creation of membership mask
            is_bf_fail = pd.Series([
                (df_comp[i], df_logged[i]) in bf_fail_keys for i in range(len(df))
            ], index=df.index)
            
            is_bf_succ = pd.Series([
                (df_comp[i], df_logged[i]) in bf_success_keys for i in range(len(df))
            ], index=df.index)

            df.loc[(eid_series == 4625) & is_bf_fail, 'AttackCategory'] = 'Brute Force — Succeeded'
            df.loc[(eid_series == 4624) & is_bf_succ, 'AttackCategory'] = 'Brute Force — Succeeded'

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

            # 🧠 Behavioral Enrichment: Include high-risk terms in the EventToken
            # This allows the ML to differentiate between "Process Create (Normal)" and "Process Create (Mimikatz)"
            risk_tokens = []
            msg_series_ml = ml_df['detail'].astype(str).str.lower() if 'detail' in ml_df.columns else pd.Series('', index=ml_df.index)
            
            for i, row in ml_df.iterrows():
                m = msg_series_ml.loc[i]
                found_risk = "none"
                if any(ext in m for ext in RANSOMWARE_EXT): found_risk = "ransom"
                elif any(p in m for p in MALWARE_PROCESSES): found_risk = "malware"
                elif any(ind in m for ind in PHISHING_INDICATORS): found_risk = "phish"
                risk_tokens.append(found_risk)
            
            ml_df['RiskToken'] = risk_tokens
            ml_df['EventToken'] = (
                ml_df['event ID'].astype(str) + '_' +
                ml_df['User'].str.split('\\').str[-1].fillna('?') + '_' +
                ml_df['RiskToken']
            )
            grouped     = ml_df.groupby(['computer', 'TimeBucket'])
            X_seq       = [g['EventToken'].tolist() for _, g in grouped]
            bucket_keys = [k for k, _ in grouped]

            if X_seq:
                try:
                    with contextlib.redirect_stdout(io.StringIO()):
                        fe    = preprocessing.FeatureExtractor()
                        x_mat = fe.fit_transform(np.array(X_seq, dtype=object),
                                                 term_weighting='tf-idf', normalization='zero-mean')
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

        out_dir  = 'detected_anomalies'
        os.makedirs(out_dir, exist_ok=True)
        ts_str   = datetime.now().strftime('%Y%m%d_%H%M%S')
        out_path = os.path.join(out_dir, f'anomalous_logs_{ts_str}.json')

        terminal_summary = capture.get_output()

        export = {
            '_terminal_summary': terminal_summary,
            '_meta': {
                'generated_at':       datetime.now().isoformat(),
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

        with open(out_path, 'w', encoding='utf-8') as f:
            json.dump(export, f, indent=4)

        print(f"\n{'='*W}")
        print(f"  💾 EXPORT → {out_path}")
        print(f"{'='*W}\n")


if __name__ == '__main__':
    run_forensic_analysis()
