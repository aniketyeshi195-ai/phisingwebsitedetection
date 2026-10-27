import re
import ipaddress
import joblib
import pandas as pd
import streamlit as st

from urllib.parse import urlparse
from datetime import datetime

# ---------------- PAGE CONFIG ----------------
st.set_page_config(
    page_title="PHISHGUARD AI | Cyber Security",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# ---------------- PREMIUM CSS ----------------
st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&family=Space+Grotesk:wght@400;500;600;700&display=swap');

:root {
    --bg: #070b14;
    --panel: #0d1424;
    --border: #202c43;
    --blue: #38bdf8;
    --purple: #8b5cf6;
    --text: #edf4ff;
    --muted: #91a2bd;
}

.stApp {
    background:
        radial-gradient(ellipse at 10% 0%, #142449 0%, transparent 38%),
        radial-gradient(ellipse at 90% 10%, #201344 0%, transparent 30%),
        var(--bg);
    color: var(--text);
    font-family: 'Inter', sans-serif;
}

.block-container {
    max-width: 1400px;
    padding-top: 1.8rem;
    padding-bottom: 3rem;
}

h1, h2, h3 {
    font-family: 'Space Grotesk', sans-serif !important;
    color: var(--text) !important;
}

[data-testid="stSidebar"] {
    background: #090f1d;
    border-right: 1px solid var(--border);
}

[data-testid="stSidebar"] * {
    color: var(--text);
}

.brand {
    font-family: 'Space Grotesk', sans-serif;
    font-size: 25px;
    font-weight: 800;
    letter-spacing: 1px;
    background: linear-gradient(90deg, #ffffff, #38bdf8, #a78bfa);
    -webkit-background-clip: text;
    -webkit-text-fill-color: transparent;
}

.eyebrow {
    color: var(--blue);
    font-size: 12px;
    font-weight: 800;
    letter-spacing: 3px;
    text-transform: uppercase;
}

.hero-title {
    font-family: 'Space Grotesk', sans-serif;
    font-size: clamp(35px, 5vw, 62px);
    line-height: 1.08;
    font-weight: 800;
    letter-spacing: -2px;
    margin: 14px 0;
}

.gradient-text {
    background: linear-gradient(90deg, #38bdf8, #a78bfa);
    -webkit-background-clip: text;
    -webkit-text-fill-color: transparent;
}

.hero-subtitle {
    color: #a3b4cc;
    font-size: 16px;
    line-height: 1.8;
    max-width: 700px;
}

.hero-card {
    padding: 30px;
    border: 1px solid #263654;
    border-radius: 24px;
    background: linear-gradient(135deg, #111d34dd, #0b1120ee);
    box-shadow: 0 20px 70px #00000030;
    margin-bottom: 25px;
}

.panel {
    background: linear-gradient(145deg, #101a2c, #0b1220);
    border: 1px solid var(--border);
    border-radius: 18px;
    padding: 22px;
    margin-bottom: 18px;
}

.panel-title {
    color: #eaf3ff;
    font-size: 17px;
    font-weight: 700;
    margin-bottom: 8px;
}

.muted {
    color: var(--muted);
    font-size: 13px;
    line-height: 1.7;
}

.status-pill {
    display: inline-block;
    border: 1px solid #24516b;
    background: #0c2636;
    color: #67d7ff;
    border-radius: 30px;
    padding: 7px 13px;
    font-size: 11px;
    font-weight: 800;
    letter-spacing: 1px;
}

.stTextInput input {
    background: #080f1c !important;
    color: white !important;
    border: 1px solid #2a3a55 !important;
    border-radius: 12px !important;
    min-height: 52px;
}

.stTextInput input:focus {
    border-color: #38bdf8 !important;
    box-shadow: 0 0 0 2px #38bdf822 !important;
}

.stButton > button {
    background: linear-gradient(100deg, #0284c7, #6d5dfc);
    color: white;
    border: none;
    border-radius: 12px;
    min-height: 48px;
    font-weight: 800;
    transition: 0.2s ease;
}

.stButton > button:hover {
    transform: translateY(-2px);
    box-shadow: 0 8px 25px #2563eb50;
    color: white;
    border: none;
}

div[data-testid="stMetric"] {
    background: linear-gradient(145deg, #111c30, #0b1220);
    border: 1px solid #26344c;
    border-radius: 16px;
    padding: 19px;
}

div[data-testid="stMetricLabel"] {
    color: #9eb0ca !important;
}

div[data-testid="stMetricValue"] {
    color: #f1f7ff !important;
    font-family: 'Space Grotesk', sans-serif;
}

.result-safe {
    background: linear-gradient(120deg, #062d29, #0b1d26);
    border: 1px solid #10b98180;
    border-radius: 20px;
    padding: 26px;
}

.result-danger {
    background: linear-gradient(120deg, #3a111c, #21121f);
    border: 1px solid #fb718580;
    border-radius: 20px;
    padding: 26px;
}

.result-unknown {
    background: linear-gradient(120deg, #352710, #211b14);
    border: 1px solid #fbbf2480;
    border-radius: 20px;
    padding: 26px;
}

.footer {
    text-align: center;
    color: #6f829f;
    font-size: 12px;
    padding: 30px 0 10px;
    border-top: 1px solid #202c43;
    margin-top: 35px;
}

#MainMenu, footer {
    visibility: hidden;
}

@media (max-width: 768px) {
    .hero-card { padding: 20px; }
    .hero-title { letter-spacing: -1px; }
}
</style>
""", unsafe_allow_html=True)


# ---------------- URL FEATURE EXTRACTION ----------------
def extract_features(url):
    url = str(url).strip()

    parsed = urlparse(
        url if "://" in url else "http://" + url
    )

    host = (parsed.hostname or "").lower()
    path = parsed.path or ""
    query = parsed.query or ""

    try:
        ipaddress.ip_address(host)
        is_ip = 1
    except ValueError:
        is_ip = 0

    digits = sum(c.isdigit() for c in url)
    letters = sum(c.isalpha() for c in url)
    special = sum(not c.isalnum() for c in url)

    suspicious_words = [
        "login", "verify", "account", "secure", "update",
        "password", "bank", "confirm", "signin", "wallet"
    ]

    return {
        "url_length": len(url),
        "domain_length": len(host),
        "is_ip": is_ip,
        "is_https": int(parsed.scheme.lower() == "https"),
        "dot_count": host.count("."),
        "hyphen_count": host.count("-"),
        "at_count": url.count("@"),
        "question_count": url.count("?"),
        "equal_count": url.count("="),
        "ampersand_count": url.count("&"),
        "digit_count": digits,
        "letter_count": letters,
        "digit_ratio": digits / max(len(url), 1),
        "special_ratio": special / max(len(url), 1),
        "subdomain_count": max(len(host.split(".")) - 2, 0),
        "path_length": len(path),
        "query_length": len(query),
        "percent_count": url.count("%"),
        "suspicious_word_count": sum(
            word in url.lower() for word in suspicious_words
        ),
        "double_slash_in_path": int("//" in path),
    }


# ---------------- LOAD MODEL ----------------
@st.cache_resource
def load_model():
    saved = joblib.load("url_model.pkl")

    if isinstance(saved, dict):
        return saved["model"], saved["features"]

    # Backward compatibility if only a model was saved
    return saved, None


try:
    model, saved_features = load_model()
    model_error = None
except Exception as exc:
    model = None
    saved_features = None
    model_error = str(exc)


# ---------------- SESSION STATE ----------------
if "history" not in st.session_state:
    st.session_state.history = []

if "scan_result" not in st.session_state:
    st.session_state.scan_result = None


# ---------------- SIDEBAR ----------------
with st.sidebar:
    st.markdown(
        '<div class="brand">🛡 PHISHGUARD AI</div>',
        unsafe_allow_html=True
    )

    st.markdown("---")
    st.markdown("### NAVIGATION")

    page = st.radio(
        "Choose a section",
        ["🔍 URL Scanner", "📊 Scan History", "ℹ️ About Project"],
        label_visibility="collapsed"
    )

    st.markdown("---")

    if model is not None:
        st.markdown(
            '<span class="status-pill">● MODEL LOADED</span>',
            unsafe_allow_html=True
        )
        st.caption("Machine learning model is ready.")
    else:
        st.error("Model could not be loaded.")
        st.caption("Check that url_model.pkl exists.")

    st.markdown("---")
    st.markdown("**PROJECT**")
    st.caption("AI-powered phishing URL detection")
    st.caption("Academic demonstration prototype")


# ---------------- HEADER ----------------
st.markdown(
    '<div class="eyebrow">NEXT-GEN WEB SECURITY</div>',
    unsafe_allow_html=True
)

if page == "🔍 URL Scanner":

    st.markdown("""
    <div class="hero-card">
        <div class="hero-title">
            One link can change<br>
            <span class="gradient-text">everything.</span>
        </div>
        <div class="hero-subtitle">
            Detect suspicious URLs with machine learning.
            Analyze URL characteristics and get a quick
            risk assessment before trusting an unfamiliar link.
        </div>
        <br>
        <span class="status-pill">✦ AI-POWERED URL ANALYSIS</span>
    </div>
    """, unsafe_allow_html=True)

    total_scans = len(st.session_state.history)
    phishing_scans = sum(
        item["prediction"] == "Potentially Phishing"
        for item in st.session_state.history
    )
    safe_scans = sum(
        item["prediction"] == "Likely Legitimate"
        for item in st.session_state.history
    )

    c1, c2, c3 = st.columns(3)

    c1.metric("TOTAL SCANS", total_scans)
    c2.metric("PHISHING FLAGS", phishing_scans)
    c3.metric("LEGITIMATE FLAGS", safe_scans)

    st.markdown("<br>", unsafe_allow_html=True)

    left, right = st.columns([1.65, 1])

    with left:
        st.markdown("""
        <div class="panel">
            <div class="panel-title">🔎 Website Risk Scanner</div>
            <div class="muted">
                Paste a URL below to begin the analysis.
                Do not open a suspicious link to test it.
            </div>
        </div>
        """, unsafe_allow_html=True)

        with st.form("scanner_form"):
            entered_url = st.text_input(
                "Website URL",
                placeholder="https://example.com",
                help="Enter the URL you want to assess."
            )

            scan_clicked = st.form_submit_button(
                "⚡ SCAN WEBSITE",
                use_container_width=True
            )

        if scan_clicked:
            st.session_state.scan_result = None

            raw_url = entered_url.strip()

            if not raw_url:
                st.warning("Please enter a URL first.")

            elif any(char.isspace() for char in raw_url):
                st.error("URL cannot contain spaces.")

            elif not re.match(
                r"^https?://", raw_url, flags=re.IGNORECASE
            ):
                normalized_url = "https://" + raw_url
                raw_url = normalized_url

            if raw_url and model is not None and not any(
                char.isspace() for char in raw_url
            ):
                parsed_check = urlparse(raw_url)

                if (
                    parsed_check.scheme.lower() not in ["http", "https"]
                    or not parsed_check.hostname
                    or "." not in parsed_check.hostname
                ):
                    st.error("Please enter a valid website URL.")
                else:
                    try:
                        progress = st.progress(0)
                        status = st.empty()

                        status.info("Initializing URL analysis...")
                        progress.progress(25)

                        features = extract_features(raw_url)
                        feature_df = pd.DataFrame([features])

                        if saved_features:
                            feature_df = feature_df.reindex(
                                columns=saved_features,
                                fill_value=0
                            )

                        status.info("Analyzing URL characteristics...")
                        progress.progress(60)

                        prediction = int(
                            model.predict(feature_df)[0]
                        )

                        probabilities = model.predict_proba(
                            feature_df
                        )[0]

                        classes = list(model.classes_)
                        prob_map = {
                            int(cls): float(prob)
                            for cls, prob in zip(classes, probabilities)
                        }

                        confidence = prob_map.get(prediction, 0.0) * 100

                        status.info("Preparing assessment...")
                        progress.progress(100)
                        status.empty()
                        progress.empty()

                        # Dataset label: 0 = phishing, 1 = legitimate
                        if prediction == 0:
                            verdict = "Potentially Phishing"
                        else:
                            verdict = "Likely Legitimate"

                        result = {
                            "url": raw_url,
                            "prediction": verdict,
                            "confidence": round(confidence, 2),
                            "time": datetime.now().strftime(
                                "%d %b %Y, %I:%M %p"
                            ),
                            "features": features,
                            "probabilities": prob_map
                        }

                        st.session_state.scan_result = result
                        st.session_state.history.insert(0, result)
                        st.session_state.history = (
                            st.session_state.history[:20]
                        )

                    except Exception as exc:
                        st.error(f"Analysis failed: {exc}")

        # RESULTS
        result = st.session_state.scan_result

        if result:
            st.markdown("<br>", unsafe_allow_html=True)

            if result["prediction"] == "Potentially Phishing":
                st.markdown(f"""
                <div class="result-danger">
                    <div style="font-size:42px">⚠️</div>
                    <div style="font-size:24px;font-weight:800;color:#fda4af">
                        Potentially Phishing
                    </div>
                    <p style="color:#fecdd3">
                        The model detected patterns associated with
                        phishing URLs. Avoid entering personal information.
                    </p>
                    <b>Model confidence: {result["confidence"]:.2f}%</b>
                </div>
                """, unsafe_allow_html=True)

            else:
                st.markdown(f"""
                <div class="result-safe">
                    <div style="font-size:42px">🛡️</div>
                    <div style="font-size:24px;font-weight:800;color:#6ee7b7">
                        Likely Legitimate
                    </div>
                    <p style="color:#bbf7d0">
                        The model classified this URL as legitimate.
                        This does not guarantee the website is safe.
                    </p>
                    <b>Model confidence: {result["confidence"]:.2f}%</b>
                </div>
                """, unsafe_allow_html=True)

            st.markdown("<br>", unsafe_allow_html=True)
            st.markdown("#### 🧬 URL Feature Analysis")

            f = result["features"]

            a, b, c = st.columns(3)
            a.metric("URL LENGTH", f["url_length"])
            b.metric("HTTPS", "Yes" if f["is_https"] else "No")
            c.metric("IP ADDRESS", "Yes" if f["is_ip"] else "No")

            d, e, g = st.columns(3)
            d.metric("SUBDOMAINS", f["subdomain_count"])
            e.metric("DIGITS", f["digit_count"])
            g.metric("SUSPICIOUS WORDS", f["suspicious_word_count"])

            with st.expander("View model probability details"):
                st.write(
                    "Phishing probability:",
                    f'{result["probabilities"].get(0, 0)*100:.2f}%'
                )
                st.write(
                    "Legitimate probability:",
                    f'{result["probabilities"].get(1, 0)*100:.2f}%'
                )
                st.caption(
                    "Probabilities are model estimates, not verified "
                    "real-world safety scores."
                )

    with right:
        st.markdown("""
        <div class="panel">
            <div class="panel-title">⚙️ How it works</div>
            <br>
            <div style="color:#38bdf8;font-weight:700">
                01 &nbsp; URL INPUT
            </div>
            <div class="muted">Provide the website address.</div>
            <br>
            <div style="color:#38bdf8;font-weight:700">
                02 &nbsp; FEATURE EXTRACTION
            </div>
            <div class="muted">
                Analyze URL length, symbols, domain and other patterns.
            </div>
            <br>
            <div style="color:#38bdf8;font-weight:700">
                03 &nbsp; ML CLASSIFICATION
            </div>
            <div class="muted">
                The trained Random Forest model predicts a class.
            </div>
            <br>
            <div style="color:#38bdf8;font-weight:700">
                04 &nbsp; RISK ASSESSMENT
            </div>
            <div class="muted">
                Display the predicted result and model probabilities.
            </div>
        </div>
        """, unsafe_allow_html=True)

        st.markdown("""
        <div class="panel">
            <div class="panel-title">🔐 Security Reminder</div>
            <p class="muted">
                Never share your password, OTP, banking details or
                private information with an unfamiliar website.
            </p>
            <p class="muted">
                A legitimate prediction is not a guarantee.
                This prototype analyzes URL features only and does
                not verify the website's live content or reputation.
            </p>
        </div>
        """, unsafe_allow_html=True)


elif page == "📊 Scan History":
    st.markdown("""
    <div class="hero-card">
        <div class="hero-title">
            Scan <span class="gradient-text">History</span>
        </div>
        <div class="hero-subtitle">
            Review the results from your current session.
        </div>
    </div>
    """, unsafe_allow_html=True)

    if st.session_state.history:
        history_df = pd.DataFrame([
            {
                "Time": item["time"],
                "URL": item["url"],
                "Prediction": item["prediction"],
                "Confidence": f'{item["confidence"]:.2f}%'
            }
            for item in st.session_state.history
        ])

        st.dataframe(
            history_df,
            use_container_width=True,
            hide_index=True
        )

        if st.button("🗑️ Clear History"):
            st.session_state.history = []
            st.session_state.scan_result = None
            st.rerun()
    else:
        st.info("No scans yet. Visit URL Scanner to get started.")


elif page == "ℹ️ About Project":
    st.markdown("""
    <div class="hero-card">
        <div class="hero-title">
            About <span class="gradient-text">PHISHGUARD AI</span>
        </div>
        <div class="hero-subtitle">
            An academic project demonstrating how machine learning
            can classify URLs based on extracted features.
        </div>
    </div>
    """, unsafe_allow_html=True)

    st.markdown("### Project Overview")
    st.write(
        "PhishGuard AI is a prototype designed to help users "
        "understand potential phishing risks in website URLs. "
        "It extracts selected URL characteristics and uses a "
        "trained Random Forest classifier to predict a class."
    )

    col1, col2 = st.columns(2)

    with col1:
        st.markdown("""
        <div class="panel">
            <div class="panel-title">🧠 Technology Stack</div>
            <p class="muted">
                Python · Streamlit · Pandas · Scikit-learn · Joblib
            </p>
        </div>
        """, unsafe_allow_html=True)

    with col2:
        st.markdown("""
        <div class="panel">
            <div class="panel-title">🎯 Project Objective</div>
            <p class="muted">
                Demonstrate URL feature extraction and ML-based
                phishing classification in an interactive interface.
            </p>
        </div>
        """, unsafe_allow_html=True)

    st.warning(
        "This is an educational prototype, not a certified security "
        "product. Do not rely on it as the only way to judge a website."
    )


# ---------------- FOOTER ----------------
st.markdown("""
<div class="footer">
    🛡 PHISHGUARD AI &nbsp; | &nbsp; AI-POWERED URL RISK ASSESSMENT
    <br><br>
    Built for educational and research purposes.
</div>
""", unsafe_allow_html=True)