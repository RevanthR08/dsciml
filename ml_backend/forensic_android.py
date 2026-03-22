import sys, os, contextlib, io, json
import pandas as pd
import numpy as np
from datetime import datetime, timedelta

sys.path.append(os.getcwd())

from log_analyzer.models import IsolationForest
from log_analyzer import preprocessing

# Check for command-line argument first, then environment variable, else use default
if len(sys.argv) > 1 and os.path.isfile(sys.argv[1]):
    log_file = sys.argv[1]
else:
    log_file = os.getenv('SOC_LOG_FILE')

THREAT_METADATA = {
    'Fatal System Crash':        {'MitreID': 'T1499',   'Tactic': 'Impact',               'Risk': 9},
    'Seccomp Policy Violation':  {'MitreID': 'T1562.001', 'Tactic': 'Defense Evasion',    'Risk': 7},
    'App Operational Failure':   {'MitreID': 'T1499',   'Tactic': 'Impact',               'Risk': 5},
    'Root Compromise':           {'MitreID': 'T1068',   'Tactic': 'Privilege Escalation', 'Risk': 10},
    'SELinux Disabled':          {'MitreID': 'T1562.001', 'Tactic': 'Defense Evasion',    'Risk': 8},
    'Mock Location Active':      {'MitreID': 'T1562',   'Tactic': 'Defense Evasion',      'Risk': 7},
    'ADB Debugging Enabled':     {'MitreID': 'T1569',   'Tactic': 'Execution',            'Risk': 5},
    'Developer Options Enabled': {'MitreID': 'T1569',   'Tactic': 'Execution',            'Risk': 3},
    'High Risk Score':           {'MitreID': 'T1437',   'Tactic': 'Execution',            'Risk': 6},
    'Normal':                    {'MitreID': 'None',    'Tactic': 'None',                 'Risk': 0},
}


def pkg_bucket(p) -> str:
    p = str(p).lower().strip()
    if not p or p in ('nan', 'none'):
        return 'UNKNOWN'
    if 'google' in p or p.startswith('com.google'):
        return 'GOOGLE_CORE'
    if p.startswith('com.android.') or 'system_server' in p or p.endswith('.shell'):
        return 'SYSTEM'
    return 'THIRD_PARTY'


def detail_bucket(d) -> str:
    d = str(d).lower()
    if 'fatal signal' in d or 'sigsys' in d:
        return 'FATAL'
    if 'seccomp' in d:
        return 'SECCOMP'
    if 'nullpointer' in d or 'exception' in d:
        return 'EXCEPTION'
    if 'permission' in d or 'denied' in d:
        return 'PERMISSION'
    return 'NORMAL'


def apply_threats(df_in: pd.DataFrame) -> pd.DataFrame:
    df_in = df_in.copy()
    df_in['AttackCategory'] = 'Normal'
    df_in['TempRisk'] = 0

    def apply(condition, category):
        if category not in THREAT_METADATA:
            return
        risk = THREAT_METADATA[category]['Risk']
        mask = condition & (risk > df_in['TempRisk'])
        df_in.loc[mask, 'AttackCategory'] = category
        df_in.loc[mask, 'TempRisk'] = risk

    detail = df_in.get('detail', pd.Series('', index=df_in.index)).astype(str).str.lower()

    # --- Behavioral (log text / tag / package context) ---
    apply(detail.str.contains(r'fatal signal|sigsys', na=False, regex=True), 'Fatal System Crash')
    apply(detail.str.contains('seccomp prevented call', na=False), 'Seccomp Policy Violation')
    apply(detail.str.contains('nullpointerexception', na=False), 'App Operational Failure')

    # --- Posture (numeric) ---
    root = pd.to_numeric(df_in.get('root', 0), errors='coerce').fillna(0)
    adb = pd.to_numeric(df_in.get('adb', 0), errors='coerce').fillna(0)
    dev = pd.to_numeric(df_in.get('devOpts', df_in.get('devopts', 0)), errors='coerce').fillna(0)
    selinux = pd.to_numeric(df_in.get('selinux', 0), errors='coerce').fillna(0)
    mock = pd.to_numeric(df_in.get('mock', 0), errors='coerce').fillna(0)
    score = pd.to_numeric(df_in.get('score', 0), errors='coerce').fillna(0)

    apply(root == 1, 'Root Compromise')
    apply((root == 1) & (selinux == 0), 'SELinux Disabled')
    apply((mock == 1) & (adb == 1), 'Mock Location Active')
    apply((adb == 1) & (root == 1), 'ADB Debugging Enabled')
    apply(dev == 1, 'Developer Options Enabled')
    apply((score < 30) & (root == 1), 'High Risk Score')

    df_in.drop(columns=['TempRisk'], inplace=True)
    return df_in


def load_android_csv_for_db(path: str) -> pd.DataFrame | None:
    """
    Load an Android CSV, normalize headers, and return a DataFrame ready for
    apply_threats (same shape as run_android_forensics uses). None on failure.
    """
    try:
        df = pd.read_csv(path, low_memory=False)
    except Exception:
        return None
    if df.empty:
        return None

    df.columns = [str(c).strip().lower() for c in df.columns]

    col_map = {
        'logged': next((c for c in df.columns if c in ('timestamp', 'logged', 'time')), None),
        'level': next((c for c in df.columns if c == 'level'), None),
        'tag': next((c for c in df.columns if c == 'tag'), None),
        'package': next((c for c in df.columns if c in ('package_r', 'package_name', 'package')), None),
        'detail': next((c for c in df.columns if c == 'detail'), None),
    }

    def _col_series(key, default=''):
        name = col_map.get(key)
        if name and name in df.columns:
            return df[name].fillna(default)
        return pd.Series(default, index=df.index)

    df['detail'] = _col_series('detail', '')
    df['level'] = _col_series('level', 'INFO')
    df['tag'] = _col_series('tag', 'unknown')
    pkg_src = col_map.get('package')
    if pkg_src and pkg_src in df.columns:
        df['package_r'] = df[pkg_src].astype(str).fillna('')
    else:
        df['package_r'] = ''

    ts_col = col_map.get('logged')
    if ts_col and ts_col in df.columns:
        df['logged'] = pd.to_datetime(df[ts_col], errors='coerce')
    else:
        start_time = datetime.now() - timedelta(minutes=len(df))
        df['logged'] = [start_time + timedelta(minutes=i) for i in range(len(df))]

    df = df.dropna(subset=['logged'])

    for posture in ('root', 'selinux', 'adb', 'mock', 'score'):
        if posture not in df.columns:
            df[posture] = 0
        df[posture] = pd.to_numeric(df[posture], errors='coerce').fillna(0)

    if 'devopts' in df.columns:
        df['devOpts'] = pd.to_numeric(df['devopts'], errors='coerce').fillna(0)
    else:
        df['devOpts'] = 0

    for legacy in ('penalty', 'temp', 'ram'):
        if legacy not in df.columns:
            df[legacy] = 0
        df[legacy] = pd.to_numeric(df[legacy], errors='coerce').fillna(0)

    if 'net' not in df.columns:
        df['net'] = ''
    else:
        s = df['net'].astype(str).fillna('')
        df['net'] = s.where(s.str.lower() != 'nan', '')

    for c in ('pid', 'tid'):
        if c in df.columns:
            df[c] = pd.to_numeric(df[c], errors='coerce')
        else:
            df[c] = np.nan

    if 'label' not in df.columns:
        df['label'] = ''
    else:
        df['label'] = df['label'].astype(str).str.strip().str.lower()

    return df


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


def run_android_forensics_from_path(
    csv_path: str, *, display_name: str | None = None, write_json: bool = True
) -> dict | None:
    W = 82
    capture = TerminalCapture()
    shown_name = display_name or csv_path

    with contextlib.redirect_stdout(capture):
        print("\n" + "="*W)
        print("  📱  ANDROID FORENSICS SYSTEM  v2.0  —  BEHAVIORAL & POSTURE")
        print("="*W)
        print(f"  📁 File : {shown_name}")

        df = load_android_csv_for_db(csv_path)
        if df is None:
            print("  ❌ Cannot load CSV.")
            return None

        print(f"  📊 Logs : {len(df):,}")
        if len(df) == 0:
            print("  ⚠️ Warning: File is empty or could not be parsed correctly.")
            return None

        pkg_src = next(
            (c for c in df.columns if c in ('package_r', 'package_name', 'package')),
            None,
        )

        df['computer'] = 'Android Device'
        df['User'] = 'MobileUser'
        df['event ID'] = df['score'].astype(int)
        df['task Category'] = 'Android Behavioral'

        print("="*W)
        print(f"  📋 Normalized columns; package source={pkg_src!r}")
        print("  🔠 Running Android behavioral + posture classification...")

        df = apply_threats(df)

        # Behavior token for sequence ML (level_pkg_tag_detail signal)
        df['tag_clean'] = df['tag'].astype(str).str.replace(r'[/_]\d+', '', regex=True).fillna('unknown')
        df['pkg_bucket'] = df['package_r'].apply(pkg_bucket)
        df['detail_signal'] = df['detail'].apply(detail_bucket)
        df['BehaviorToken'] = (
            df['level'].astype(str).str.upper().str.replace(' ', '_', regex=False)
            + '_' + df['pkg_bucket'].astype(str)
            + '_' + df['tag_clean'].astype(str).str.replace(' ', '_', regex=False)
            + '_' + df['detail_signal'].astype(str)
        )

        df['TimeBucket'] = df['logged'].dt.floor('1min')

        df['MitreID'] = df['AttackCategory'].map(lambda x: THREAT_METADATA.get(x, {}).get('MitreID', '?'))
        df['Tactic'] = df['AttackCategory'].map(lambda x: THREAT_METADATA.get(x, {}).get('Tactic', '?'))
        df['RiskScore'] = df['AttackCategory'].map(lambda x: THREAT_METADATA.get(x, {}).get('Risk', 0))

        summary = df['AttackCategory'].value_counts()

        print(f"\n{'─'*W}")
        print("  🚨 RULE-BASED DETECTION  (Android behavioral + posture)")
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

        active_rule_count = len([c for c in summary.index if c != 'Normal' and summary[c] > 0])
        total_logs = len(df)
        threat_density = round(total_risk_score / (total_logs / 1000), 2) if total_logs > 0 else 0
        normalized_density = round(threat_density / active_rule_count, 2) if active_rule_count > 0 else 0

        print(f"{'─'*W}")
        print(f"  🔴 Total Threats         : {total_suspicious:,}")
        print(f"  🟢 Normal Activity       : {summary.get('Normal', 0):,}")
        print(f"  🔥 Cumulative Risk Score : {total_risk_score:,}")

        print(f"\n{'='*W}")
        print("  🤖 ML VALIDATION  (Isolation Forest — BehaviorToken sequences)")
        print(f"{'='*W}")

        anomaly_count = 0
        agreement_rate = 0

        if len(df) > 10:
            ml_df = df.copy()
            if len(df) > 50000:
                print(f"  ⚡ Massive dataset detected. Sampling 50,000 rows for ML speed...")
                ml_df = df.sample(50000, random_state=42).sort_values('logged')

            grouped = ml_df.groupby(['computer', 'TimeBucket'])
            X_seq = [g['BehaviorToken'].tolist() for _, g in grouped]
            bucket_keys = [k for k, _ in grouped]

            if X_seq:
                try:
                    with contextlib.redirect_stdout(io.StringIO()):
                        fe = preprocessing.FeatureExtractor()
                        x_mat = fe.fit_transform(
                            np.array(X_seq, dtype=object),
                            term_weighting='binary',
                            normalization='zero-mean',
                        )
                        if x_mat.shape[0] > 0:
                            model = IsolationForest(contamination=0.1, random_state=42)
                            model.fit(x_mat)
                            y_pred = model.predict(x_mat)
                            anomaly_count = int(np.sum(y_pred == 1))
                            ml_flagged_buckets = {bucket_keys[i] for i, flag in enumerate(y_pred) if flag == 1}

                    rule_flagged_df = df[df['AttackCategory'] != 'Normal']
                    rule_flagged_buckets = set(zip(rule_flagged_df['computer'], rule_flagged_df['TimeBucket']))
                    overlap = rule_flagged_buckets & ml_flagged_buckets
                    agreement_rate = round(len(overlap) / max(len(rule_flagged_buckets), 1) * 100, 1)

                    print(f"  ✅ ML flagged         : {anomaly_count:,} anomalous 1-min windows")
                    print(f"  📏 Rule-flagged windows: {len(rule_flagged_buckets):,}")
                    print(f"  🤝 Rule-ML Agreement  : {agreement_rate}%")
                except Exception as e:
                    print(f"  ⚠️ Behavioral ML failed ({e}); falling back to numeric posture features.")
                    numeric_cols = ['score', 'penalty', 'root', 'selinux', 'adb', 'devOpts', 'mock', 'temp', 'ram']
                    mat = df[numeric_cols].fillna(0).values
                    try:
                        model = IsolationForest(contamination=0.1, random_state=42)
                        model.fit(mat)
                        y_pred = model.predict(mat)
                        anomaly_count = int(np.sum(y_pred == 1))
                        ml_flagged_idx = set(np.where(y_pred == 1)[0])
                        rule_flagged_idx = set(df.index[df['AttackCategory'] != 'Normal'].tolist())
                        agreement_rate = round(len(ml_flagged_idx & rule_flagged_idx) / max(len(rule_flagged_idx), 1) * 100, 1)
                        print(f"  ✅ ML flagged (numeric): {anomaly_count:,} rows")
                        print(f"  🤝 Rule-ML Agreement  : {agreement_rate}%")
                    except Exception as e2:
                        print(f"  ⚠️ Numeric ML also failed: {e2}")
            else:
                print("  ⚠️ No sequences for behavioral ML.")
        else:
            print("  ⚠️ Skipping ML Validation: Insufficient data.")

        print(f"\n{'='*W}")
        print("  ⏱️  ATTACK TIMELINE  (highest-risk events)")
        print(f"{'='*W}")

        anomalous_df = df[df['AttackCategory'] != 'Normal'].sort_values('logged')
        timeline_df = anomalous_df.sort_values('RiskScore', ascending=False)

        shown = 0
        for _, row in timeline_df.iterrows():
            risk = row['RiskScore']
            bar = '█' * risk + '░' * (10 - risk)
            ts = pd.to_datetime(row['logged']).strftime('%Y-%m-%d %H:%M:%S')
            print(f"  [{ts}]  {row['AttackCategory']:<28}  {bar} R{risk:<2}  "
                  f"🖥 {row['computer']:<16}  👤 {row['User']}")
            shown += 1
            if shown >= 20:
                print(f"  ... ({len(timeline_df) - shown:,} more events — see JSON for full timeline)")
                break

        if shown == 0:
            print("  No timestamped threats found.")

        terminal_summary = capture.get_output()

        export = {
            '_terminal_summary': terminal_summary,
            '_meta': {
                'generated_at': datetime.now().isoformat(),
                'log_platform': 'android',
                'total_logs': len(df),
                'total_threats': total_suspicious,
                'risk_score': total_risk_score,
                'threat_density': threat_density,
                'normalized_density': normalized_density,
                'active_rules': active_rule_count,
                'rule_ml_agreement': f"{agreement_rate}%",
            },
            '_attack_chains': [],
            '_impossible_travel': [],
        }

        for cat, grp in anomalous_df.groupby('AttackCategory'):
            meta = THREAT_METADATA.get(cat, {})
            grp = grp.copy()
            grp['logged'] = grp['logged'].astype(str)
            export[cat] = {
                'mitre_id': meta.get('MitreID', '?'),
                'tactic': meta.get('Tactic', '?'),
                'risk_score': meta.get('Risk', 0),
                'count': len(grp),
                'events': grp[['logged', 'event ID', 'User', 'computer',
                               'task Category', 'MitreID', 'Tactic', 'RiskScore']]
                .to_dict(orient='records'),
            }

        if write_json:
            out_dir = 'detected_anomalies'
            os.makedirs(out_dir, exist_ok=True)
            ts_str = datetime.now().strftime('%Y%m%d_%H%M%S')
            out_path = os.path.join(out_dir, f'anomalous_logs_{ts_str}.json')
            with open(out_path, 'w', encoding='utf-8') as f:
                json.dump(export, f, indent=4)
            print(f"\n{'='*W}")
            print(f"  💾 EXPORT → {out_path}")
            print(f"{'='*W}\n")

        return export


def run_android_forensics():
    run_android_forensics_from_path(log_file, display_name=log_file, write_json=True)


def run_android_forensic_analysis(
    file_bytes: bytes, filename: str = "upload.csv", return_dict: bool = True
):
    """In-memory Android CSV analysis; same export shape as disk-based CLI run."""
    if not return_dict:
        raise ValueError("Only return_dict=True is supported for API use.")
    import tempfile

    with tempfile.NamedTemporaryFile(mode="wb", suffix=".csv", delete=False) as tf:
        tf.write(file_bytes)
        path = tf.name
    try:
        return run_android_forensics_from_path(
            path, display_name=filename, write_json=False
        )
    finally:
        try:
            os.unlink(path)
        except OSError:
            pass


if __name__ == '__main__':
    run_android_forensics()
