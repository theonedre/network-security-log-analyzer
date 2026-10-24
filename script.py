import re
from pathlib import Path

import pandas as pd
import streamlit as st


st.set_page_config(
    page_title="Network and Security Log Analyzer",
    page_icon="🔍",
    layout="wide",
)

st.title("Network and Security Log Analyzer")

LOG_SOURCES = [
    "Generic",
    "Cisco IOS",
    "Cisco ASA",
    "Palo Alto Firewall",
    "Fortinet FortiGate",
    "Linux Syslog",
    "Windows Event Log Export",
    "Wazuh",
    "Splunk Export",
]

log_source = st.selectbox("Select the log source", LOG_SOURCES)

uploaded_file = st.file_uploader(
    "Upload a log file",
    type=["log", "txt", "csv", "json"],
)

search_terms = st.text_input(
    "Enter keywords or phrases",
    placeholder='Example: failed login, interface down, denied, "authentication failure"',
)

search_mode = st.radio(
    "Search mode",
    ["Any keyword", "All keywords", "Exact phrase", "Regular expression"],
    horizontal=True,
)

case_sensitive = st.checkbox("Case-sensitive search", value=False)


def read_uploaded_file(file) -> pd.DataFrame:
    """
    Read an uploaded log file and return a DataFrame containing
    a line number and raw log message.
    """
    suffix = Path(file.name).suffix.lower()

    if suffix == ".csv":
        dataframe = pd.read_csv(file)

        # Combine all columns so the entire event can be searched.
        dataframe["raw_event"] = dataframe.astype(str).agg(" | ".join, axis=1)
        dataframe.insert(0, "line_number", range(1, len(dataframe) + 1))
        return dataframe

    if suffix == ".json":
        try:
            dataframe = pd.read_json(file, lines=True)
        except ValueError:
            file.seek(0)
            dataframe = pd.read_json(file)

        dataframe["raw_event"] = dataframe.astype(str).agg(" | ".join, axis=1)
        dataframe.insert(0, "line_number", range(1, len(dataframe) + 1))
        return dataframe

    raw_text = file.getvalue().decode("utf-8", errors="replace")
    lines = raw_text.splitlines()

    return pd.DataFrame(
        {
            "line_number": range(1, len(lines) + 1),
            "raw_event": lines,
        }
    )


def split_search_terms(text: str) -> list[str]:
    """
    Split search input while preserving phrases enclosed in quotes.
    """
    return re.findall(r'"([^"]+)"|(\S+)', text)


def normalize_terms(term_groups: list[tuple[str, str]]) -> list[str]:
    """
    Convert regex tuple results into a clean list of search terms.
    """
    terms = []

    for quoted_term, normal_term in term_groups:
        value = quoted_term or normal_term

        if value:
            terms.append(value)

    return terms


def filter_logs(
    dataframe: pd.DataFrame,
    query: str,
    mode: str,
    case_sensitive_search: bool,
) -> pd.DataFrame:
    """
    Filter raw log events using keywords, phrases, or regex.
    """
    if not query.strip():
        return dataframe.copy()

    flags = 0 if case_sensitive_search else re.IGNORECASE

    if mode == "Regular expression":
        try:
            pattern = re.compile(query, flags)
        except re.error as error:
            raise ValueError(f"Invalid regular expression: {error}") from error

        mask = dataframe["raw_event"].astype(str).apply(
            lambda event: bool(pattern.search(event))
        )

        return dataframe[mask].copy()

    parsed_terms = split_search_terms(query)
    terms = normalize_terms(parsed_terms)

    if not terms:
        return dataframe.copy()

    def event_matches(event: str) -> bool:
        comparison_event = event if case_sensitive_search else event.lower()
        comparison_terms = (
            terms
            if case_sensitive_search
            else [term.lower() for term in terms]
        )

        if mode == "Any keyword":
            return any(term in comparison_event for term in comparison_terms)

        if mode == "All keywords":
            return all(term in comparison_event for term in comparison_terms)

        if mode == "Exact phrase":
            phrase = query.strip().strip('"')
            comparison_phrase = (
                phrase if case_sensitive_search else phrase.lower()
            )
            return comparison_phrase in comparison_event

        return False

    mask = dataframe["raw_event"].astype(str).apply(event_matches)
    return dataframe[mask].copy()


if uploaded_file is not None:
    try:
        logs_df = read_uploaded_file(uploaded_file)

        st.success(
            f"Loaded {len(logs_df):,} log events from "
            f"{uploaded_file.name} as {log_source} logs."
        )

        if st.button("Parse Logs", type="primary"):
            filtered_df = filter_logs(
                dataframe=logs_df,
                query=search_terms,
                mode=search_mode,
                case_sensitive_search=case_sensitive,
            )

            total_events = len(logs_df)
            matching_events = len(filtered_df)

            column1, column2, column3 = st.columns(3)

            column1.metric("Total Events", f"{total_events:,}")
            column2.metric("Matching Events", f"{matching_events:,}")
            column3.metric(
                "Match Percentage",
                f"{(matching_events / total_events * 100):.2f}%"
                if total_events
                else "0.00%",
            )

            st.subheader("Matching Log Events")

            st.dataframe(
                filtered_df,
                use_container_width=True,
                hide_index=True,
            )

            csv_data = filtered_df.to_csv(index=False).encode("utf-8")

            st.download_button(
                label="Export Filtered Results",
                data=csv_data,
                file_name="filtered_log_results.csv",
                mime="text/csv",
            )

    except (ValueError, UnicodeDecodeError, pd.errors.ParserError) as error:
        st.error(f"Unable to process the file: {error}")

else:
    st.info("Upload a supported log file to begin.")



