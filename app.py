import streamlit as st
import pandas as pd
import io
import os
from domain_analyzer import DomainAnalyzer
from utils import parse_domain_list

def main():
    st.set_page_config(
        page_title="Domain Upgrade Finder",
        page_icon="🔍",
        layout="wide"
    )
    
    st.title("🔍 Domain Upgrade Finder")
    st.markdown("Analyze your keywords and find potential buyers by checking if businesses ranking on Google could upgrade to domains with those keywords.")
    
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
            "Serper API Key", 
            value=os.getenv("SERPER_API_KEY", ""),
            type="password",
            help="Get your API key from https://serper.dev/api-key"
        )
        
        if not api_key:
            st.error("Please provide a valid Serper API key to continue.")
            st.stop()
        
        # Initialize analyzer
        if st.session_state.analyzer is None or st.session_state.analyzer.api_key != api_key:
            st.session_state.analyzer = DomainAnalyzer(api_key)
        
        st.subheader("Settings")
        max_results = st.slider("Max Google Results", 5, 20, 10)
        show_progress = st.checkbox("Show Progress", value=True)
        filter_matches = st.checkbox("Show only keywords with matches", value=False)
    
    # Main content area
    col1, col2 = st.columns([1, 1])
    
    with col1:
        st.subheader("Input Keywords")
        
        # Option 1: File upload
        uploaded_file = st.file_uploader(
            "Upload keyword list (CSV/TXT)",
            type=['csv', 'txt'],
            help="Upload a file with one set of keywords per line"
        )
        
        # Option 2: Text input
        manual_input = st.text_area(
            "Or paste keywords manually (one set per line)",
            height=200,
            placeholder="houston plumber services\naffordable concrete services\nbest lawyer firm"
        )
        
        # Process input
        keyword_sets = []
        if uploaded_file:
            try:
                if uploaded_file.name.endswith('.csv'):
                    df = pd.read_csv(uploaded_file)
                    if len(df.columns) > 0:
                        keyword_sets = df.iloc[:, 0].astype(str).tolist()
                else:
                    content = uploaded_file.read().decode('utf-8')
                    keyword_sets = parse_domain_list(content)
            except Exception as e:
                st.error(f"Error reading file: {str(e)}")
        
        elif manual_input.strip():
            keyword_sets = parse_domain_list(manual_input)
        
        # Validate keyword sets
        if keyword_sets:
            valid_keyword_sets = []
            invalid_keyword_sets = []
            
            for keywords in keyword_sets:
                keywords = keywords.strip()
                if keywords and len(keywords.split()) >= 1:
                    valid_keyword_sets.append(keywords)
                else:
                    invalid_keyword_sets.append(keywords)
            
            if valid_keyword_sets:
                st.success(f"✅ {len(valid_keyword_sets)} valid keyword sets found")
                if invalid_keyword_sets:
                    st.warning(f"⚠️ {len(invalid_keyword_sets)} invalid keyword sets skipped")
                    with st.expander("Show invalid keyword sets"):
                        for keywords in invalid_keyword_sets:
                            st.text(keywords)
            else:
                st.error("No valid keyword sets found")
                st.stop()
        else:
            st.info("Please upload a file or enter keywords manually to get started.")
            st.stop()
    
    with col2:
        st.subheader("Analysis")
        
        if st.button("🚀 Start Analysis", type="primary", width='stretch'):
            if not valid_keyword_sets:
                st.error("No valid keyword sets to analyze")
                st.stop()
            
            # Progress tracking
            progress_bar = st.progress(0) if show_progress else None
            status_text = st.empty() if show_progress else None
            
            try:
                results = []
                total_keyword_sets = len(valid_keyword_sets)
                
                for i, keywords in enumerate(valid_keyword_sets):
                    if show_progress and progress_bar is not None and status_text is not None:
                        progress = (i + 1) / total_keyword_sets
                        progress_bar.progress(progress)
                        status_text.text(f"Analyzing '{keywords}' ({i + 1}/{total_keyword_sets})")
                    
                    # Analyze keywords
                    keyword_results = st.session_state.analyzer.analyze_keywords(
                        keywords, 
                        max_results=max_results
                    )
                    
                    if keyword_results:
                        results.extend(keyword_results)
                
                if show_progress and progress_bar is not None and status_text is not None:
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
                st.metric("Total Keyword Sets Analyzed", int(st.session_state.results['Keywords'].nunique()))
            with col2:
                st.metric("Upgrade Opportunities", len(df))
            with col3:
                keywords_with_matches = len(set(df[df['Match_Count'] > 0]['Keywords'].tolist())) if len(df[df['Match_Count'] > 0]) > 0 else 0
                st.metric("Keywords with Matches", keywords_with_matches)
            
            # Display table
            st.dataframe(
                df,
                width='stretch',
                column_config={
                    "Keywords": "Your Keywords",
                    "Competitor_Domain": "Competitor Domain",
                    "Search_Keywords": "Processed Keywords",
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
                    file_name="keyword_upgrade_opportunities.csv",
                    mime="text/csv",
                    width='stretch'
                )
            
            with col2:
                # Excel export
                import tempfile
                import os as temp_os
                with tempfile.NamedTemporaryFile(delete=False, suffix='.xlsx') as tmp_file:
                    df.to_excel(tmp_file.name, sheet_name='Upgrade Opportunities', index=False, engine='openpyxl')
                    with open(tmp_file.name, 'rb') as f:
                        excel_data = f.read()
                    temp_os.unlink(tmp_file.name)
                
                st.download_button(
                    label="📊 Download Excel",
                    data=excel_data,
                    file_name="keyword_upgrade_opportunities.xlsx",
                    mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                    width='stretch'
                )

if __name__ == "__main__":
    main()
