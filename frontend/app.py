"""ScamShield AI investigation workstation."""

import html
import os
import sys
from pathlib import Path

from dotenv import load_dotenv

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

load_dotenv(ROOT / ".env")

import streamlit as st

from frontend.api_client import ApiError, ScamShieldClient

CONTENT_LIMIT = 20_000
EVIDENCE_TYPES = ("EMAIL", "SMS", "ADVERTISEMENT")
EXAMPLES = {
    "EMAIL": (
        "Subject: Urgent account review\n\n"
        "Dear customer, your mailbox will be closed today unless you confirm "
        "your password at http://mailbox-check.example. This is a fictional example."
    ),
    "SMS": (
        "Parcel held. Pay the release fee now at http://delivery-fee.example "
        "or the package will be returned. This is a fictional example."
    ),
    "ADVERTISEMENT": (
        "Guaranteed return of 40 percent this week. Send a deposit to the "
        "wallet listed here and a manager will double it. This is a fictional example."
    ),
}
RISK_STYLES = {
    "HIGH": ("#7f1d1d", "#f8e6e6"),
    "MEDIUM": ("#7a5410", "#f8f1df"),
    "LOW": ("#1d5c38", "#e5f3eb"),
    "INCONCLUSIVE": ("#334155", "#e7edf3"),
}

st.set_page_config(
    page_title="ScamShield AI",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)


def inject_styles() -> None:
    st.markdown(
        """
        <style>
          .block-container { padding-top: 1.4rem; max-width: 1180px; }
          .banner {
            background: #f8f1e3;
            border: 1px solid #c4a15a;
            border-radius: 12px;
            padding: 0.85rem 1rem;
            margin-bottom: 1rem;
          }
          .banner strong { color: #7a5410; }
          .kicker {
            letter-spacing: 0.08em;
            text-transform: uppercase;
            font-size: 0.75rem;
            color: #0f5c59;
            font-weight: 700;
            margin-bottom: 0.15rem;
          }
          .badge {
            display: inline-block;
            padding: 0.18rem 0.55rem;
            border-radius: 999px;
            font-size: 0.78rem;
            font-weight: 700;
            letter-spacing: 0.03em;
          }
          div[data-testid="stTextArea"] textarea { font-family: ui-monospace, monospace; }
        </style>
        """,
        unsafe_allow_html=True,
    )


def client_from_state() -> ScamShieldClient:
    return ScamShieldClient(
        base_url=st.session_state.api_url,
        api_key=st.session_state.api_key,
    )


def open_case(case_id: str) -> None:
    st.session_state.selected_case_id = case_id
    st.session_state.view = "Investigations"


def close_case() -> None:
    st.session_state.selected_case_id = None


def load_example(evidence_type: str) -> None:
    st.session_state.draft_content = EXAMPLES[evidence_type]


def clear_draft() -> None:
    st.session_state.draft_content = ""


def badge(label: str | None, kind: str | None = None) -> str:
    text = html.escape(label or "Not recorded")
    color, background = RISK_STYLES.get(kind or "", ("#334155", "#e7edf3"))
    return (
        f'<span class="badge" style="color:{color};background:{background};">'
        f"{text}</span>"
    )


def report_download_name(case_id: str, report_id: str) -> str:
    """Return a filename that is safe to offer as a browser download."""
    safe_case = "".join(
        char if char.isalnum() or char in "-_" else "_" for char in case_id
    )[:64] or "case"
    safe_report = "".join(
        char if char.isalnum() or char in "-_" else "_" for char in report_id
    )[:8] or "report"
    return f"scamshield-{safe_case}-{safe_report}.pdf"


def show_api_error(error: ApiError) -> None:
    if error.status_code == 409:
        st.error(
            "This case already has a completed analysis. Turn on "
            "\"Replace a completed analysis\" to replace that advisory result. "
            "The preserved evidence stays unchanged."
        )
        return
    st.error(error.message)
    if error.case_id:
        st.button(
            "Open preserved investigation",
            on_click=open_case,
            args=(error.case_id,),
            key=f"open-preserved-{error.case_id}",
        )


def sidebar() -> None:
    st.sidebar.markdown('<div class="kicker">ScamShield AI</div>', unsafe_allow_html=True)
    st.sidebar.markdown("**Investigation workstation**")
    st.sidebar.caption("Advisory review of suspicious email, SMS, and advertisements.")
    st.sidebar.radio(
        "Navigate",
        ["New investigation", "Investigations", "About"],
        key="view",
    )
    st.sidebar.divider()
    st.sidebar.text_input("API URL", key="api_url")
    st.sidebar.text_input(
        "API key",
        type="password",
        key="api_key",
        help="Leave this blank when the backend has no SCAMSHIELD_API_KEY.",
    )
    try:
        health = client_from_state().health()
        if health.get("status") == "ok":
            st.sidebar.success("API connected")
        else:
            st.sidebar.warning("API responded without an ok status.")
    except ApiError as error:
        st.sidebar.error(error.message)


def banner() -> None:
    st.markdown(
        """
        <div class="banner">
          <strong>Advisory analysis only.</strong>
          A result does not prove fraud and does not decide whether text was
          written by AI. Submitted text is stored with a SHA-256 digest and a
          UTC collection time. That digest can detect later changes to the
          stored text. It is not a certified chain of custody.
        </div>
        """,
        unsafe_allow_html=True,
    )


def render_new_investigation() -> None:
    st.markdown('<div class="kicker">New investigation</div>', unsafe_allow_html=True)
    st.header("Preserve and analyze content")
    banner()
    evidence_type = st.selectbox("Evidence type", EVIDENCE_TYPES)
    example_col, clear_col = st.columns([1, 1])
    with example_col:
        st.button(
            "Load a fictional example",
            on_click=load_example,
            args=(evidence_type,),
        )
    with clear_col:
        st.button("Clear draft", on_click=clear_draft)

    content = st.text_area(
        "Evidence text",
        height=240,
        key="draft_content",
        placeholder="Paste the email, SMS, or advertisement exactly as received.",
    )
    st.caption(f"{len(content):,} / {CONTENT_LIMIT:,} characters")
    if st.button("Preserve and analyze", type="primary"):
        stripped = content.strip()
        if not stripped:
            st.warning("Enter the evidence text before submitting.")
            return
        if len(content) > CONTENT_LIMIT:
            st.warning(f"Evidence must be {CONTENT_LIMIT:,} characters or fewer.")
            return
        try:
            result = client_from_state().analyze(evidence_type, content)
        except ApiError as error:
            show_api_error(error)
            return
        st.session_state.last_result = result
        st.success("Evidence preserved. The advisory result is below.")

    result = st.session_state.get("last_result")
    if result:
        render_result_summary(result)
        st.button(
            "Open this investigation",
            on_click=open_case,
            args=(result["case_id"],),
        )


def render_result_summary(result: dict) -> None:
    st.markdown(
        f"{badge(result.get('risk_level'), result.get('risk_level'))} "
        f"{badge(result.get('analysis_status'))} "
        f"{badge(result.get('analysis_provider') or 'provider not recorded')}",
        unsafe_allow_html=True,
    )
    st.subheader(result.get("scam_type") or "No scam type recorded")
    st.write(result.get("summary") or "No summary recorded.")
    st.caption(result.get("message") or "")
    indicators = result.get("indicators") or []
    if indicators:
        st.markdown("**Indicators**")
        for indicator in indicators:
            st.code(indicator.get("evidence_quote") or "", language=None)
            st.write(indicator.get("explanation") or "")
    _write_list("Recommended actions", result.get("recommended_actions"))
    _write_list("Limitations", result.get("limitations"))


def _write_list(title: str, items: list[str] | None) -> None:
    if not items:
        return
    st.markdown(f"**{title}**")
    for item in items:
        st.write(f"- {item}")


def render_investigations() -> None:
    st.markdown('<div class="kicker">Investigations</div>', unsafe_allow_html=True)
    st.header("Preserved cases")
    banner()
    try:
        cases = client_from_state().list_cases()
    except ApiError as error:
        show_api_error(error)
        return

    if not cases:
        st.info("No investigations yet. Preserve a message from New investigation.")
        return

    filter_col, status_col, search_col = st.columns([1, 1, 2])
    with filter_col:
        evidence_filter = st.selectbox("Type", ["All", *EVIDENCE_TYPES])
    with status_col:
        statuses = ["All", *sorted({case["analysis_status"] for case in cases})]
        status_filter = st.selectbox("Status", statuses)
    with search_col:
        query = st.text_input("Case ID contains").strip().lower()

    filtered = []
    for case in cases:
        if evidence_filter != "All" and case["evidence_type"] != evidence_filter:
            continue
        if status_filter != "All" and case["analysis_status"] != status_filter:
            continue
        if query and query not in case["case_id"].lower():
            continue
        filtered.append(case)

    st.caption(f"{len(filtered)} shown of {len(cases)} stored")
    for case in filtered:
        title = (
            f"{case['evidence_type']} · {case['analysis_status']} · "
            f"{case.get('risk_level') or 'NO RISK'} · {case['case_id']}"
        )
        with st.expander(title, expanded=case["case_id"] == st.session_state.selected_case_id):
            st.markdown(
                f"{badge(case.get('risk_level'), case.get('risk_level'))} "
                f"{badge(case['evidence_type'])}",
                unsafe_allow_html=True,
            )
            st.caption(
                f"Created {case['created_at']} · "
                f"Provider {case.get('analysis_provider') or 'not recorded'}"
            )
            st.write(case.get("summary") or "No summary stored.")
            st.button(
                "Open case",
                key=f"open-{case['case_id']}",
                on_click=open_case,
                args=(case["case_id"],),
            )

    if st.session_state.selected_case_id:
        st.divider()
        render_case(st.session_state.selected_case_id)


def render_case(case_id: str) -> None:
    api = client_from_state()
    try:
        case = api.get_case(case_id)
        events = api.events(case_id)
        reports = api.list_reports(case_id)
    except ApiError as error:
        show_api_error(error)
        return

    st.markdown('<div class="kicker">Case file</div>', unsafe_allow_html=True)
    st.header(case_id)
    st.button("Close case", on_click=close_case)
    st.markdown(
        f"{badge(case.get('risk_level'), case.get('risk_level'))} "
        f"{badge(case['analysis_status'])} "
        f"{badge(case['evidence_type'])} "
        f"{badge(case.get('analysis_provider') or 'provider not recorded')}",
        unsafe_allow_html=True,
    )

    meta_col, hash_col = st.columns(2)
    with meta_col:
        st.markdown("**Record**")
        st.write(f"Created: {case['created_at']}")
        st.write(f"Collected: {case.get('evidence_collected_at') or 'Not recorded'}")
        st.write(f"Scam type: {case.get('scam_type') or 'Not recorded'}")
    with hash_col:
        st.markdown("**SHA-256 baseline**")
        st.code(case.get("evidence_sha256") or "Not recorded", language=None)

    st.markdown("**Stored evidence**")
    st.text_area(
        "Stored evidence",
        value=case["original_content"],
        height=220,
        disabled=True,
        label_visibility="collapsed",
    )
    render_result_summary(case)

    action_col, retry_col, report_col = st.columns(3)
    with action_col:
        if st.button("Verify integrity", key=f"verify-{case_id}"):
            try:
                st.session_state[f"integrity-{case_id}"] = api.verify(case_id)
            except ApiError as error:
                show_api_error(error)
            else:
                st.rerun()
    with retry_col:
        replace_completed = st.checkbox(
            "Replace a completed analysis",
            key=f"replace-{case_id}",
            help="Keeps the original evidence. The previous advisory summary is recorded as an event.",
        )
        if st.button("Run analysis again", key=f"retry-{case_id}"):
            try:
                st.session_state[f"retry-{case_id}-result"] = api.reanalyze(
                    case_id, replace_completed=replace_completed
                )
                st.rerun()
            except ApiError as error:
                show_api_error(error)
    with report_col:
        if st.button("Generate PDF report", key=f"report-{case_id}"):
            try:
                created = api.create_report(case_id)
                pdf = api.download_report(case_id, created["report_id"])
                st.session_state[f"pdf-{case_id}"] = (created, pdf)
                st.rerun()
            except ApiError as error:
                show_api_error(error)

    integrity = st.session_state.get(f"integrity-{case_id}")
    if integrity:
        status_name = integrity["integrity_status"]
        st.markdown(f"**Integrity:** {badge(status_name)}", unsafe_allow_html=True)
        if status_name == "VERIFIED":
            st.success(integrity["message"])
        elif status_name == "FAILED":
            st.error(integrity["message"])
        else:
            st.warning(integrity["message"])
        st.caption(
            f"Recorded {integrity.get('original_sha256') or 'none'} · "
            f"Calculated {integrity.get('calculated_sha256') or 'none'} · "
            f"Verified {integrity['verified_at']}"
        )

    pdf_state = st.session_state.get(f"pdf-{case_id}")
    if pdf_state:
        created, pdf = pdf_state
        st.download_button(
            "Download latest generated PDF",
            data=pdf,
            file_name=report_download_name(case_id, created["report_id"]),
            mime="application/pdf",
            key=f"download-{case_id}-{created['report_id']}",
        )
        st.caption(f"Report SHA-256: {created['content_sha256']}")

    if reports:
        st.markdown("**Stored reports**")
        for report in reports:
            label = f"Prepare download · {report['generated_at']}"
            if st.button(label, key=f"load-report-{report['report_id']}"):
                try:
                    pdf = api.download_report(case_id, report["report_id"])
                except ApiError as error:
                    show_api_error(error)
                else:
                    st.session_state[f"stored-pdf-{report['report_id']}"] = pdf
            stored_pdf = st.session_state.get(f"stored-pdf-{report['report_id']}")
            if stored_pdf:
                st.download_button(
                    "Download this PDF",
                    data=stored_pdf,
                    file_name=report_download_name(case_id, report["report_id"]),
                    mime="application/pdf",
                    key=f"download-stored-{report['report_id']}",
                )
                st.caption(report["content_sha256"])

    st.markdown("**Event history**")
    if events:
        st.dataframe(
            [
                {
                    "Time (UTC)": event["event_timestamp"],
                    "Event": event["event_type"],
                    "Details": event["details"],
                }
                for event in events
            ],
            width="stretch",
            hide_index=True,
        )
    else:
        st.caption("No events are stored for this case.")


def render_about() -> None:
    st.markdown('<div class="kicker">About</div>', unsafe_allow_html=True)
    st.header("What this workstation does")
    banner()
    st.markdown(
        """
        ScamShield AI preserves a submitted email, SMS, or advertisement and
        asks the configured provider for an advisory reading of possible scam
        or phishing indicators.

        **The application does**
        - Store the exact submitted text.
        - Record a SHA-256 digest of that UTF-8 text and a UTC collection time.
        - Compare the stored text with that digest later.
        - Keep a history of collection, analysis, verification, and report events.
        - Generate a downloadable PDF advisory report.
        - Use the mock provider offline, or the OpenAI Responses API when you configure it.

        **The application does not**
        - Prove that content is fraudulent.
        - Decide whether a person or an AI wrote the text.
        - Visit links in the evidence.
        - Provide a confidence score.
        - Train a model.
        - Provide a certified chain of custody or an independently verified collection time.

        The hash and the evidence live in the same SQLite database. Someone who
        can change the database can change both. A matching hash shows that the
        stored text still matches the recorded digest. It does not show who
        collected it.

        Set `AI_PROVIDER=mock` for labeled placeholder results. Set
        `AI_PROVIDER=openai` with your own `OPENAI_API_KEY` and `OPENAI_MODEL`
        when you want a live advisory reading. The browser never receives the
        model key. Set `SCAMSHIELD_API_KEY` on the backend, and the same value
        in the sidebar, before exposing the API beyond this machine.
        """
    )


def main() -> None:
    st.session_state.setdefault(
        "api_url", os.getenv("SCAMSHIELD_API_URL", "http://127.0.0.1:8000")
    )
    st.session_state.setdefault("api_key", os.getenv("SCAMSHIELD_API_KEY", ""))
    st.session_state.setdefault("view", "New investigation")
    st.session_state.setdefault("selected_case_id", None)
    st.session_state.setdefault("draft_content", "")
    inject_styles()
    sidebar()
    view = st.session_state.view
    if view == "New investigation":
        render_new_investigation()
    elif view == "Investigations":
        render_investigations()
    else:
        render_about()


main()
