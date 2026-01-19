"""
Log Sensitivity Analyzer - Interactive Forensic Dashboard

This Streamlit application provides a comprehensive, forensic-grade interface
for PII and secret detection in log files. It integrates all project phases
(2-5) with visual analytics and real-time scanning capabilities.

Compliance: KVKK/GDPR Data Protection Standards
Author: Senior Security UI/UX Developer
"""

import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import json
import sys
import subprocess
from pathlib import Path
from datetime import datetime
from io import StringIO

# Add project paths
project_root = Path(__file__).parent.parent.parent
sys.path.insert(0, str(project_root))
sys.path.insert(0, str(project_root / 'src' / 'core'))
sys.path.insert(0, str(project_root / 'src' / 'validators'))

# Import project modules
from automation import (
    check_python_version,
    check_project_info,
    check_required_modules,
    check_validators,
    check_patterns_module,
    check_engine_module
)
from engine import LogScanner, ScanResult
from patterns import ENTROPY_THRESHOLD


# =============================================================================
# PAGE CONFIGURATION
# =============================================================================

st.set_page_config(
    page_title="Log Sensitivity Analyzer",
    page_icon="🔒",
    layout="wide",
    initial_sidebar_state="expanded",
    menu_items={
        'About': "Log Sensitivity Analyzer v1.0.0 - KVKK/GDPR Compliant DLP Tool"
    }
)


# =============================================================================
# CUSTOM CSS - CYBERSECURITY THEME
# =============================================================================

st.markdown("""
<style>
    /* Dark cybersecurity theme */
    .stApp {
        background-color: #0e1117;
    }
    
    /* Vibrant headers */
    h1, h2, h3 {
        color: #00ff00 !important;
        text-shadow: 0 0 10px #00ff0040;
    }
    
    /* Metric styling */
    [data-testid="stMetricValue"] {
        font-size: 2rem;
        color: #00ff00;
        font-weight: bold;
    }
    
    /* Success elements */
    .element-container .stSuccess {
        background-color: #00440020;
        border-left: 4px solid #00ff00;
    }
    
    /* Error elements */
    .element-container .stError {
        background-color: #44000020;
        border-left: 4px solid #ff0000;
    }
    
    /* Warning elements */
    .element-container .stWarning {
        background-color: #44440020;
        border-left: 4px solid #ffaa00;
    }
    
    /* Tables */
    .dataframe {
        border: 2px solid #00ff0060 !important;
    }
    
    /* Buttons */
    .stButton>button {
        background: linear-gradient(90deg, #00ff00, #00aa00);
        color: black;
        font-weight: bold;
        border: none;
        border-radius: 5px;
        padding: 0.5rem 1rem;
    }
    
    .stButton>button:hover {
        background: linear-gradient(90deg, #00aa00, #00ff00);
        box-shadow: 0 0 20px #00ff0060;
    }
    
    /* File uploader */
    [data-testid="stFileUploader"] {
        border: 2px dashed #00ff0060;
        border-radius: 10px;
        padding: 2rem;
    }
    
    /* Sidebar */
    section[data-testid="stSidebar"] {
        background-color: #1a1d24;
        border-right: 2px solid #00ff0040;
    }
</style>
""", unsafe_allow_html=True)


# =============================================================================
# SYSTEM INTEGRITY SIDEBAR
# =============================================================================

def render_system_checks():
    """Display environment validation checks in sidebar."""
    st.sidebar.header("🔧 System Integrity")
    
    checks = [
        ("Python Version", check_python_version),
        ("Project Metadata", check_project_info),
        ("Required Modules", check_required_modules),
        ("Validators", check_validators),
        ("Pattern Library", check_patterns_module),
        ("Engine Module", check_engine_module),
    ]
    
    all_passed = True
    for check_name, check_func in checks:
        success, message = check_func()
        if success:
            st.sidebar.success(message)
        else:
            st.sidebar.error(message)
            all_passed = False
    
    st.sidebar.markdown("---")
    
    if all_passed:
        st.sidebar.success("✅ **System Ready**")
    else:
        st.sidebar.error("❌ **System Issues Detected**")
    
    return all_passed


# =============================================================================
# MAIN DASHBOARD
# =============================================================================

def main():
    """Main dashboard application."""
    
    # Header
    st.markdown("""
    <h1 style='text-align: center; margin-bottom: 0;'>
        🔒 LOG SENSITIVITY ANALYZER
    </h1>
    <p style='text-align: center; color: #00ff00; font-size: 1.2rem; margin-top: 0;'>
        Forensic-Grade DLP for KVKK/GDPR Compliance
    </p>
    """, unsafe_allow_html=True)
    
    # Render system check sidebar
    system_ready = render_system_checks()
    
    # Compliance badges in sidebar
    st.sidebar.markdown("---")
    st.sidebar.header("📜 Compliance")
    st.sidebar.success("✓ KVKK Article 12 (Integrity)")
    st.sidebar.success("✓ GDPR Article 32 (Security)")
    st.sidebar.info("**Version**: 1.0.0")
    
    # Sidebar metrics (will be updated during scan)
    st.sidebar.markdown("---")
    st.sidebar.header("📊 Scan Metrics")
    
    # Initialize session state for scan results
    if 'scan_result' not in st.session_state:
        st.session_state.scan_result = None
    if 'findings_df' not in st.session_state:
        st.session_state.findings_df = None
    
    # =========================================================================
    # FILE UPLOAD SECTION
    # =========================================================================
    
    st.header("📁 Upload Log File")
    
    uploaded_file = st.file_uploader(
        "Drop your log file here",
        type=['log', 'txt'],
        help="Supports .log and .txt files. Processing uses line-by-line streaming for constant memory usage.",
        key="file_uploader"
    )
    
    if uploaded_file is not None:
        st.info(f"📄 **File**: {uploaded_file.name} ({uploaded_file.size / 1024:.2f} KB)")
        
        if st.button("🔍 Start Forensic Analysis", key="scan_button"):
            with st.spinner("🔬 Analyzing log file..."):
                # Create scanner
                scanner = LogScanner()
                
                # Progress tracking
                progress_bar = st.progress(0)
                status_text = st.empty()
                
                # Read file content
                content = uploaded_file.getvalue().decode('utf-8', errors='ignore')
                lines = content.split('\n')
                total_lines = len(lines)
                
                # Process line by line
                for i, line in enumerate(lines):
                    if line.strip():
                        findings = scanner.scan_line(line.strip(), i + 1)
                        scanner.findings.extend(findings)
                    
                    # Update progress
                    if i % 10 == 0 or i == total_lines - 1:
                        progress = (i + 1) / total_lines
                        progress_bar.progress(progress)
                        status_text.text(f"Scanning: {i + 1}/{total_lines} lines...")
                
                # Create result
                result = scanner._create_result(total_lines, 0.0)
                st.session_state.scan_result = result
                
                # Convert to DataFrame
                if result.findings:
                    st.session_state.findings_df = pd.DataFrame([
                        {
                            "Type": f.type.upper(),
                            "Masked Value": f.masked_value,
                            "Line": f.line_number,
                            "Verified": "✓" if f.verified else "✗",
                            "Risk": f.risk_level,
                            "Confidence": f"{f.confidence:.0%}",
                            "Weight": f.risk_weight
                        }
                        for f in result.findings
                    ])
                
                progress_bar.empty()
                status_text.empty()
                st.success(f"✅ **Scan Complete!** Analyzed {total_lines} lines in {result.summary.scan_duration:.3f}s")
    
    # =========================================================================
    # RESULTS DISPLAY
    # =========================================================================
    
    if st.session_state.scan_result is not None:
        result = st.session_state.scan_result
        
        # Update sidebar metrics
        st.sidebar.metric("Lines Scanned", result.summary.total_lines)
        st.sidebar.metric("Total Matches", result.summary.total_matches)
        st.sidebar.metric("Verified", result.summary.verified_matches)
        
        # Risk score with color
        risk_score = result.summary.risk_score
        if risk_score >= 5.0:
            st.sidebar.error(f"Risk Score: **{risk_score:.2f}/10.0**")
        elif risk_score >= 3.0:
            st.sidebar.warning(f"Risk Score: **{risk_score:.2f}/10.0**")
        else:
            st.sidebar.success(f"Risk Score: **{risk_score:.2f}/10.0**")
        
        st.sidebar.markdown(f"**Category**: {result.summary.risk_category}")
        
        # =====================================================================
        # LIVE METRICS
        # =====================================================================
        
        st.header("📈 Scan Results")
        
        col1, col2, col3, col4 = st.columns(4)
        
        with col1:
            st.metric("Lines Scanned", result.summary.total_lines)
        
        with col2:
            st.metric("Total Matches", result.summary.total_matches)
        
        with col3:
            st.metric("Verified Matches", result.summary.verified_matches)
        
        with col4:
            st.metric("Risk Score", f"{risk_score:.2f}/10.0")
        
        # =====================================================================
        # FINDINGS TABLE
        # =====================================================================
        
        st.markdown("---")
        st.header("📋 Detailed Findings")
        
        if st.session_state.findings_df is not None and len(st.session_state.findings_df) > 0:
            df = st.session_state.findings_df
            
            # Color styling function
            def color_risk(row):
                colors = {
                    'CRITICAL': 'background-color: #ff000040',
                    'HIGH': 'background-color: #ff990040',
                    'MEDIUM': 'background-color: #ffcc0040',
                    'LOW': 'background-color: #00ff0040'
                }
                color = colors.get(row['Risk'], '')
                return [color] * len(row)
            
            # Display styled table
            styled_df = df.style.apply(color_risk, axis=1)
            st.dataframe(styled_df, use_container_width=True, height=400)
            
            # Download findings as CSV
            csv = df.to_csv(index=False)
            st.download_button(
                label="📥 Download Findings (CSV)",
                data=csv,
                file_name=f"findings_{datetime.now():%Y%m%d_%H%M%S}.csv",
                mime="text/csv"
            )
        else:
            st.info("✅ No sensitive data detected in this log file.")
        
        # =====================================================================
        # VISUAL ANALYTICS
        # =====================================================================
        
        if result.findings and len(result.findings) > 0:
            st.markdown("---")
            st.header("📊 Visual Analytics")
            
            col1, col2 = st.columns(2)
            
            # PIE CHART: Distribution by Type
            with col1:
                st.subheader("🥧 PII Type Distribution")
                type_counts = pd.Series(result.summary.findings_by_type)
                
                fig = px.pie(
                    values=type_counts.values,
                    names=type_counts.index,
                    title="Findings by Type",
                    color_discrete_sequence=px.colors.sequential.Viridis
                )
                fig.update_layout(
                    plot_bgcolor='rgba(0,0,0,0)',
                    paper_bgcolor='rgba(0,0,0,0)',
                    font_color='#00ff00'
                )
                st.plotly_chart(fig, use_container_width=True)
            
            # BAR CHART: Risk Levels
            with col2:
                st.subheader("📊 Risk Level Distribution")
                risk_counts = df['Risk'].value_counts()
                
                colors_map = {
                    'CRITICAL': '#ff0000',
                    'HIGH': '#ff9900',
                    'MEDIUM': '#ffcc00',
                    'LOW': '#00ff00'
                }
                
                fig = px.bar(
                    x=risk_counts.index,
                    y=risk_counts.values,
                    title="Findings by Risk Level",
                    color=risk_counts.index,
                    color_discrete_map=colors_map,
                    labels={'x': 'Risk Level', 'y': 'Count'}
                )
                fig.update_layout(
                    plot_bgcolor='rgba(0,0,0,0)',
                    paper_bgcolor='rgba(0,0,0,0)',
                    font_color='#00ff00',
                    showlegend=False
                )
                st.plotly_chart(fig, use_container_width=True)
            
            # ENTROPY PLOT (if entropy data available)
            entropy_findings = [f for f in result.findings if f.entropy is not None]
            if entropy_findings:
                st.subheader("🔬 Shannon Entropy Analysis")
                
                entropy_df = pd.DataFrame([
                    {
                        "Value": f.masked_value,
                        "Entropy": f.entropy,
                        "Type": f.type
                    }
                    for f in entropy_findings
                ])
                
                fig = px.scatter(
                    entropy_df,
                    x=range(len(entropy_df)),
                    y="Entropy",
                    color="Type",
                    hover_data=["Value"],
                    title=f"Entropy Distribution (Threshold: {ENTROPY_THRESHOLD} bits)",
                    labels={'x': 'Finding Index', 'y': 'Entropy (bits)'}
                )
                
                # Add threshold line
                fig.add_hline(
                    y=ENTROPY_THRESHOLD,
                    line_dash="dash",
                    line_color="#ff0000",
                    annotation_text=f"High-Entropy Threshold ({ENTROPY_THRESHOLD} bits)",
                    annotation_position="right"
                )
                
                fig.update_layout(
                    plot_bgcolor='rgba(0,0,0,0)',
                    paper_bgcolor='rgba(0,0,0,0)',
                    font_color='#00ff00'
                )
                
                st.plotly_chart(fig, use_container_width=True)
        
        # =====================================================================
        # JSON EXPORT
        # =====================================================================
        
        st.markdown("---")
        st.header("📥 Export Reports")
        
        col1, col2 = st.columns(2)
        
        with col1:
            # JSON Export
            json_output = {
                "scan_metadata": {
                    "timestamp": result.timestamp,
                    "tool_version": result.tool_version,
                    "compliance_framework": result.compliance_framework,
                    "filename": uploaded_file.name if uploaded_file else "unknown"
                },
                "findings": [
                    {
                        "type": f.type,
                        "masked_value": f.masked_value,
                        "line_number": f.line_number,
                        "verified": f.verified,
                        "confidence": f.confidence,
                        "risk_level": f.risk_level,
                        "risk_weight": f.risk_weight,
                        "context": f.context,
                        "entropy": f.entropy
                    }
                    for f in result.findings
                ],
                "summary": {
                    "total_lines": result.summary.total_lines,
                    "total_matches": result.summary.total_matches,
                    "verified_matches": result.summary.verified_matches,
                    "risk_score": result.summary.risk_score,
                    "risk_category": result.summary.risk_category,
                    "findings_by_type": result.summary.findings_by_type,
                    "scan_duration": result.summary.scan_duration
                }
            }
            
            st.download_button(
                label="📄 Download JSON Report",
                data=json.dumps(json_output, indent=2),
                file_name=f"scan_report_{datetime.now():%Y%m%d_%H%M%S}.json",
                mime="application/json"
            )
    
    # =========================================================================
    # AUDIT SECTION
    # =========================================================================
    
    st.markdown("---")
    st.header("🔍 System Audit")
    
    col1, col2 = st.columns(2)
    
    with col1:
        if st.button("▶️ Run Full Audit", key="audit_button"):
            with st.spinner("Running comprehensive test suite..."):
                try:
                    # Run test suite
                    result = subprocess.run(
                        ['./run_tests.sh'],
                        capture_output=True,
                        text=True,
                        cwd=str(project_root),
                        timeout=30
                    )
                    
                    if result.returncode == 0:
                        st.success("✅ **ALL TESTS PASSED** - System integrity verified!")
                        st.balloons()
                    else:
                        st.error("❌ **Some tests failed** - Review required")
                    
                    # Show output in expander
                    with st.expander("📋 View Test Details"):
                        st.code(result.stdout, language='bash')
                        if result.stderr:
                            st.code(result.stderr, language='bash')
                
                except subprocess.TimeoutExpired:
                    st.error("⏱️ Test execution timed out")
                except Exception as e:
                    st.error(f"❌ Error running tests: {e}")
    
    with col2:
        if st.button("🔄 Refresh System Checks", key="refresh_button"):
            st.rerun()
    
    # Footer
    st.markdown("---")
    st.markdown("""
    <div style='text-align: center; color: #00ff0080; padding: 2rem;'>
        <p>🔒 Log Sensitivity Analyzer v1.0.0</p>
        <p>Compliance: KVKK Article 12 + GDPR Article 32</p>
        <p>© 2026 Senior Security Engineering Team</p>
    </div>
    """, unsafe_allow_html=True)


# =============================================================================
# RUN APPLICATION
# =============================================================================

if __name__ == "__main__":
    main()
