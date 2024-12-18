import streamlit as st
from pymongo import MongoClient
import matplotlib.pyplot as plt

# MongoDB connection details
MONGO_URI = "mongodb://localhost:27017/"
DATABASE_NAME = "NLP_project"
COLLECTION_NAME = "CSV_data"

# Function to connect to MongoDB
def get_mongo_client():
    client = MongoClient(MONGO_URI)
    return client[DATABASE_NAME]

# Function to query MongoDB based on the 'id' field (CVE ID)
def query_cve_by_id(user_id):
    db = get_mongo_client()
    collection = db[COLLECTION_NAME]
    result = collection.find_one({"id": user_id})
    return result

# Function to display CVE details
def display_cve(cve):
    st.subheader(f"CVE ID: {cve['id']}")
    st.write(f"**Description:** {cve['description']}")
    st.write(f"**CVSS Score:** {cve['cvssScore']}")
    st.write(f"**Published Date:** {cve['publishedDate']}")
    st.write(f"**Affected Product:** {cve['affectedProduct']}")
    st.write(f"**Authentication Required:** {cve['authenticationRequired']}")
    st.write(f"**Access Complexity:** {cve['accessComplexity']}")
    
    # Visualizing Impact Areas using Pie Chart
    impact_data = {
        "Confidentiality": 1 if cve['confidentialityImpact'] == "Complete" else (0.5 if cve['confidentialityImpact'] == "Partial" else 0),
        "Integrity": 1 if cve['integrityImpact'] == "Complete" else (0.5 if cve['integrityImpact'] == "Partial" else 0),
        "Availability": 1 if cve['availabilityImpact'] == "Complete" else (0.5 if cve['availabilityImpact'] == "Partial" else 0)
    }
    
    labels = impact_data.keys()
    sizes = impact_data.values()
    
    fig, ax = plt.subplots()
    ax.pie(sizes, labels=labels, autopct='%1.1f%%', startangle=90, colors=["#ff9999", "#66b3ff", "#99ff99"])
    ax.axis('equal')  # Equal aspect ratio ensures that pie is drawn as a circle.
    
    st.pyplot(fig)
    
    # References
    st.write("**References:**")
    for ref in cve.get("references", []):
        st.write(f"- [{ref}]({ref})")



# Function to categorize the CVSS Score into labels
def get_cvss_label(cvss_score):
    score = float(cvss_score)
    if score == 10.0:
        return "Critical (10.0)", "red"
    elif score >= 7.0:
        return "High", "orange"
    elif score >= 4.0:
        return "Medium", "yellow"
    else:
        return "Low", "green"

# CVSS Score Visualization
def visualize_selected_cve_cvss_score(cve):
    cvss_score = cve['cvssScore']
    label, color = get_cvss_label(cvss_score)
    
    fig, ax = plt.subplots(figsize=(5, 2))  # Reduced plot size (5x2 inches)
    ax.barh([cve['id']], [float(cvss_score)], color=color, height=0.5)  # Bar chart with smaller height
    ax.set_xlabel("CVSS Score")
    ax.set_title(f"CVSS Score for {cve['id']} - {label}")
    
    # Customizing the appearance of the plot
    ax.spines['top'].set_visible(False)
    ax.spines['right'].set_visible(False)
    ax.spines['bottom'].set_visible(False)
    ax.spines['left'].set_visible(False)
    ax.tick_params(axis='both', which='both', length=0)
    
    st.pyplot(fig)
    st.write(f"**CVSS Score Label:** {label}")

# Streamlit UI
def main():
    st.title("CVE Dashboard")
    
    # User input for 'id'
    user_id = st.text_input("Enter the CVE ID to view details:", "")
    
    if user_id:
        # Query the database with the given CVE ID
        cve = query_cve_by_id(user_id)
        
        # Check if CVE exists in the database
        if cve:
            display_cve(cve)
            visualize_selected_cve_cvss_score(cve)
        else:
            st.warning(f"No CVE data found for ID: {user_id}")

# Run the Streamlit app
if __name__ == "__main__":
    main()
