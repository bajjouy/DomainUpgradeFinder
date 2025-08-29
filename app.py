import streamlit as st
import pandas as pd
import io
import os
from domain_analyzer import DomainAnalyzer
from utils import validate_domain, parse_domain_list

def main():
    st.set_page_config(
        page_title="Domain Upgrade Finder",
        page_icon="🔍",
        layout="wide"
    )
    
    st.title("🔍 Domain Upgrade Finder")
    st.markdown("Analyze your domains and find potential buyers by checking if your domains are upgrades of businesses that already rank on Google.")
    
    # Initialize session state
    if 'results' not in st.session_state:
        st.session_state.results = None
    if 'analyzer' not in st.session_state:
        st.session_state.analyzer = None
    
    # Sidebar for configuration
    with st.sidebar:
        st.header("Configuration")
        
        # API Key input
        api_key = st.text_input(
            "SerpAPI Key", 
            value=os.getenv("SERPAPI_KEY", ""),
            type="password",
            help="Get your API key from https://serpapi.com/"
        )
        
        if not api_key:
            st.error("Please provide a valid SerpAPI key to continue.")
            st.stop()
        
        # Initialize analyzer
        if st.session_state.analyzer is None or st.session_state.analyzer.api_key != api_key:
            st.session_state.analyzer = DomainAnalyzer(api_key)
        
        st.subheader("Settings")
        max_results = st.slider("Max Google Results", 5, 20, 10)
        show_progress = st.checkbox("Show Progress", value=True)
        filter_matches = st.checkbox("Show only domains with matches", value=False)
    
    # Main content area
    col1, col2 = st.columns([1, 1])
    
    with col1:
        st.subheader("Input Domains")
        
        # Option 1: File upload
        uploaded_file = st.file_uploader(
            "Upload domain list (CSV/TXT)",
            type=['csv', 'txt'],
            help="Upload a file with one domain per line"
        )
        
        # Option 2: Text input
        manual_input = st.text_area(
            "Or paste domains manually (one per line)",
            height=200,
            placeholder="HoustonPlumberServices.com\nAffordableConcreteServices.com\nBestLawyerFirm.net"
        )
        
        # Process input
        domains = []
        if uploaded_file:
            try:
                if uploaded_file.name.endswith('.csv'):
                    df = pd.read_csv(uploaded_file)
                    if len(df.columns) > 0:
                        domains = df.iloc[:, 0].astype(str).tolist()
                else:
                    content = uploaded_file.read().decode('utf-8')
                    domains = parse_domain_list(content)
            except Exception as e:
                st.error(f"Error reading file: {str(e)}")
        
        elif manual_input.strip():
            domains = parse_domain_list(manual_input)
        
        # Validate domains
        if domains:
            valid_domains = []
            invalid_domains = []
            
            for domain in domains:
                if validate_domain(domain.strip()):
                    valid_domains.append(domain.strip())
                else:
                    invalid_domains.append(domain.strip())
            
            if valid_domains:
                st.success(f"✅ {len(valid_domains)} valid domains found")
                if invalid_domains:
                    st.warning(f"⚠️ {len(invalid_domains)} invalid domains skipped")
                    with st.expander("Show invalid domains"):
                        for domain in invalid_domains:
                            st.text(domain)
            else:
                st.error("No valid domains found")
                st.stop()
        else:
            st.info("Please upload a file or enter domains manually to get started.")
            st.stop()
    
    with col2:
        st.subheader("Analysis")
        
        if st.button("🚀 Start Analysis", type="primary", use_container_width=True):
            if not valid_domains:
                st.error("No valid domains to analyze")
                st.stop()
            
            # Progress tracking
            progress_bar = st.progress(0) if show_progress else None
            status_text = st.empty() if show_progress else None
            
            try:
                results = []
                total_domains = len(valid_domains)
                
                for i, domain in enumerate(valid_domains):
                    if show_progress:
                        progress = (i + 1) / total_domains
                        progress_bar.progress(progress)
                        status_text.text(f"Analyzing {domain} ({i + 1}/{total_domains})")
                    
                    # Analyze domain
                    domain_results = st.session_state.analyzer.analyze_domain(
                        domain, 
                        max_results=max_results
                    )
                    
                    if domain_results:
                        results.extend(domain_results)
                
                if show_progress:
                    status_text.text("Analysis complete!")
                    progress_bar.progress(1.0)
                
                # Store results
                st.session_state.results = pd.DataFrame(results)
                st.success(f"Analysis complete! Found {len(results)} potential upgrade opportunities.")
                
            except Exception as e:
                st.error(f"Error during analysis: {str(e)}")
                st.stop()
    
    # Display results
    if st.session_state.results is not None and not st.session_state.results.empty:
        st.subheader("Results")
        
        df = st.session_state.results.copy()
        
        # Apply filter if requested
        if filter_matches:
            df = df[df['Match_Count'] > 0]
        
        if df.empty:
            st.info("No results match the current filters.")
        else:
            # Summary statistics
            col1, col2, col3 = st.columns(3)
            with col1:
                st.metric("Total Domains Analyzed", len(st.session_state.results['My_Domain'].unique()))
            with col2:
                st.metric("Upgrade Opportunities", len(df))
            with col3:
                domains_with_matches = len(df[df['Match_Count'] > 0]['My_Domain'].unique())
                st.metric("Domains with Matches", domains_with_matches)
            
            # Display table
            st.dataframe(
                df,
                use_container_width=True,
                column_config={
                    "My_Domain": "Your Domain",
                    "Competitor_Domain": "Competitor Domain",
                    "Keywords": "Keywords",
                    "Match_Count": st.column_config.NumberColumn(
                        "Matches",
                        format="%d"
                    ),
                    "Google_Rank": st.column_config.NumberColumn(
                        "Google Rank",
                        format="%d"
                    )
                }
            )
            
            # Export options
            st.subheader("Export Results")
            col1, col2 = st.columns(2)
            
            with col1:
                # CSV export
                csv_buffer = io.StringIO()
                df.to_csv(csv_buffer, index=False)
                csv_data = csv_buffer.getvalue()
                
                st.download_button(
                    label="📄 Download CSV",
                    data=csv_data,
                    file_name="domain_upgrade_opportunities.csv",
                    mime="text/csv",
                    use_container_width=True
                )
            
            with col2:
                # Excel export
                excel_buffer = io.BytesIO()
                with pd.ExcelWriter(excel_buffer, engine='openpyxl') as writer:
                    df.to_excel(writer, sheet_name='Upgrade Opportunities', index=False)
                excel_data = excel_buffer.getvalue()
                
                st.download_button(
                    label="📊 Download Excel",
                    data=excel_data,
                    file_name="domain_upgrade_opportunities.xlsx",
                    mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                    use_container_width=True
                )

if __name__ == "__main__":
    main()
