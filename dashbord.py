import json
import streamlit as st
import pandas as pd
import plotly.express as px

# Sample CVE JSON Data (copy the JSON data you provided above)
cve_data = [
    {
        "id": "CVE-1999-0001",
        "description": "ip_input.c in BSD-derived TCP/IP implementations allows remote attackers to cause a denial of service (crash or hang) via crafted packets.",
        "cvssScore": "5.0",
        "publishedDate": "1999-12-30",
        "affectedProduct": "bsd os 3.1",
        "authenticationRequired": "No",
        "accessComplexity": "Low",
        "confidentialityImpact": "None",
        "integrityImpact": "None",
        "availabilityImpact": "Partial",
        "references": [
            "http://www.openbsd.org/errata23.html#tcpfix",
            "http://www.osvdb.org/5707"
        ]
    },
    # Continue adding more CVE records from your dataset
]

# Convert CVE JSON data into a pandas DataFrame
df = pd.DataFrame(cve_data)

# Streamlit Web App Interface
st.title("CVE Vulnerability Dashboard")
st.write("This dashboard visualizes CVE vulnerabilities and their related data.")

# Display the CVE data as a table
st.subheader("CVE Data Table")
st.dataframe(df)

# Bar Chart: CVSS Scores for each CVE ID
st.subheader("CVSS Score by CVE ID")
fig = px.bar(df, x="id", y="cvssScore", title="CVSS Scores for CVE IDs", color="cvssScore",
             labels={"id": "CVE ID", "cvssScore": "CVSS Score"}, height=400)
st.plotly_chart(fig)

# Pie Chart: Distribution of Impact on Confidentiality, Integrity, and Availability
st.subheader("Impact Distribution")
impact_data = pd.DataFrame({
    "Impact": ["Confidentiality", "Integrity", "Availability"],
    "Complete": [
        sum(df['confidentialityImpact'] == "Complete"),
        sum(df['integrityImpact'] == "Complete"),
        sum(df['availabilityImpact'] == "Complete")
    ],
    "Partial": [
        sum(df['confidentialityImpact'] == "Partial"),
        sum(df['integrityImpact'] == "Partial"),
        sum(df['availabilityImpact'] == "Partial")
    ],
    "None": [
        sum(df['confidentialityImpact'] == "None"),
        sum(df['integrityImpact'] == "None"),
        sum(df['availabilityImpact'] == "None")
    ]
})

fig2 = px.pie(impact_data, names="Impact", values="Complete", title="Complete Impact Distribution",
              color_discrete_sequence=px.colors.sequential.RdBu)
st.plotly_chart(fig2)

fig3 = px.pie(impact_data, names="Impact", values="Partial", title="Partial Impact Distribution",
              color_discrete_sequence=px.colors.sequential.turbid)
st.plotly_chart(fig3)

fig4 = px.pie(impact_data, names="Impact", values="None", title="None Impact Distribution",
              color_discrete_sequence= px.colors.sequential.Magenta)
st.plotly_chart(fig4)

# Line Chart: CVSS Score Trend Over Time
df['publishedDate'] = pd.to_datetime(df['publishedDate'])  # Convert date to datetime
df_sorted = df.sort_values('publishedDate')  # Sort by date

st.subheader("CVSS Score Trend Over Time")
fig5 = px.line(df_sorted, x="publishedDate", y="cvssScore", title="CVSS Score Trend Over Time",
               labels={"publishedDate": "Published Date", "cvssScore": "CVSS Score"})
st.plotly_chart(fig5)

# Display affected products as a list
st.subheader("Affected Products")
st.write(df['affectedProduct'].unique())

# Display references for each CVE
st.subheader("References for CVEs")
for index, row in df.iterrows():
    st.write(f"CVE ID: {row['id']}")
    for ref in row['references']:
        st.write(f"- [Reference]({ref})")

# Streamlit Server Information
st.sidebar.title("Server Information")
st.sidebar.info("This visualization is running on a local Streamlit server.")
