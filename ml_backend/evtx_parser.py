import pandas as pd

PIPELINE_COLUMNS = ["logged", "event ID", "User", "Opcode", "task Category", "computer", "source"]


def _extract(df: pd.DataFrame, col_filters: dict) -> pd.Series:
    """Extract aa_value for rows matching all column filters, indexed by event record ID."""
    mask = pd.Series(True, index=df.index)
    for col, val in col_filters.items():
        if col not in df.columns:
            return pd.Series(dtype="string")
        mask &= df[col].fillna("").astype(str) == str(val)

    return (
        df.loc[mask, ["aa_event_record_id", "aa_value"]]
        .drop_duplicates(subset="aa_event_record_id", keep="first")
        .set_index("aa_event_record_id")["aa_value"]
    )


def parse_evtx_file(evtx_path: str) -> pd.DataFrame:
    """
    Parse a binary .evtx file into a one-row-per-event DataFrame
    with columns matching the forensic pipeline:
    logged, event ID, User, Opcode, task Category, computer, source.
    """
    from evtx2df import dataframe_from_evtx
    raw = dataframe_from_evtx(evtx_file_path=evtx_path)

    if raw.empty:
        return pd.DataFrame(columns=PIPELINE_COLUMNS)

    timestamps = raw.groupby("aa_event_record_id")["aa_timestamp"].first()

    fields = {
        "event ID": {"aa_key_1": "System", "aa_key_2": "EventID"},
        "computer": {"aa_key_1": "System", "aa_key_2": "Computer"},
        "task Category": {"aa_key_1": "System", "aa_key_2": "Task"},
        "Opcode": {"aa_key_1": "System", "aa_key_2": "Opcode"},
        "source": {"aa_key_1": "System", "aa_key_2": "Provider",
                    "aa_key_3": "#attributes", "aa_key_4": "Name"},
        "User": {"aa_key_1": "System", "aa_key_2": "Security",
                 "aa_key_3": "#attributes", "aa_key_4": "UserID"},
    }

    result = pd.DataFrame({"logged": timestamps})
    for col_name, filters in fields.items():
        result[col_name] = _extract(raw, filters)

    return result.fillna("").reset_index(drop=True)


def parse_evtx_to_csv(evtx_path: str, csv_path: str) -> int:
    """Convert a .evtx binary to CSV. Returns the number of event records written."""
    df = parse_evtx_file(evtx_path)
    df.to_csv(csv_path, index=False)
    return len(df)
