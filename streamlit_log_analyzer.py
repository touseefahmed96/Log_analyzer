import streamlit as st
import re
import matplotlib.pyplot as plt
from collections import defaultdict
import json
import os
import pandas as pd
import base64
from datetime import datetime

# Define patterns and remedies
patterns = {
    "malware": re.compile(r"malware|virus|trojan|ransomware", re.IGNORECASE),
    "file_tampering": re.compile(
        r"file tampering|unauthorized file modification", re.IGNORECASE
    ),
    "unauthorized_access": re.compile(
        r"unauthorized access|login failure|invalid login|access denied", re.IGNORECASE
    ),
    "security_breach": re.compile(
        r"security breach|data breach|intrusion detected|unauthorized entry",
        re.IGNORECASE,
    ),
    "advanced_malware": re.compile(
        r"zero-day|advanced persistent threat|rootkit", re.IGNORECASE
    ),
    "phishing": re.compile(r"phishing|spear phishing|fraudulent email", re.IGNORECASE),
    "data_leakage": re.compile(
        r"data leakage|data exfiltration|information leak", re.IGNORECASE
    ),
}

remedies = {
    "malware": "Run a full system antivirus scan, isolate the affected systems, and update your antivirus software.",
    "file_tampering": "Restore the affected files from backup, change file permissions, and monitor file integrity.",
    "unauthorized_access": "Reset passwords, implement multi-factor authentication, and review access logs.",
    "security_breach": "Disconnect affected systems from the network, conduct a thorough investigation, and notify affected parties.",
    "advanced_malware": "Employ advanced threat detection tools, perform a deep system scan, and update security protocols.",
    "phishing": "Educate users about phishing, implement email filtering solutions, and report the phishing attempt.",
    "data_leakage": "Identify the source of the leak, implement data loss prevention solutions, and review data access policies.",
}

config_file = "log_analyzer_config.json"

def load_patterns():
    global patterns, remedies
    if os.path.exists(config_file):
        with open(config_file, "r") as f:
            config = json.load(f)
            patterns.update(
                {
                    k: re.compile(v, re.IGNORECASE)
                    for k, v in config.get("patterns", {}).items()
                }
            )
            remedies.update(config.get("remedies", {}))

def save_patterns():
    config = {
        "patterns": {k: v.pattern for k, v in patterns.items()},
        "remedies": {k: v for k, v in remedies.items()},
    }
    with open(config_file, "w") as f:
        json.dump(config, f, indent=4)

# from datetime import datetime

def parse_timestamp(line):
    """
    Parse timestamps from logs with multiple formats.
    Supported formats:
    1. ISO format: "2025-01-14 06:34:31"
    2. Month abbreviation format: "Jun 21 10:00:00"
    """
    try:
        # Try parsing ISO format (e.g., "2025-01-14 06:34:31")
        if line.startswith("DEBUG:") or line.startswith("INFO:") or line.startswith("WARN:") or line.startswith("ERROR:") or line.startswith("CRITICAL:"):
            # Extract the timestamp part after "INFO:", "ERROR:", or "WARN:"
            timestamp_str = line.split()[1] + " " + line.split()[2]
            return datetime.strptime(timestamp_str, "%Y-%m-%d %H:%M:%S")
        
        # Try parsing Month abbreviation format (e.g., "Jun 21 10:00:00")
        else:
            # Extract the first three parts (month, day, time)
            timestamp_str = " ".join(line.split()[:3])
            return datetime.strptime(timestamp_str, "%b %d %H:%M:%S")
    
    except (IndexError, ValueError):
        # If parsing fails, return None
        return None

def filter_logs_by_time(log_file_content, start_time, end_time):
    filtered_logs = []
    for line in log_file_content:
        timestamp = parse_timestamp(line)
        if timestamp and start_time <= timestamp.time() < end_time:
            filtered_logs.append(line)
    return filtered_logs

def analyze_log_file(log_file):
    suspicious_activity = defaultdict(int)
    suspicious_lines = defaultdict(list)
    total_lines = 0
    for line_number, line in enumerate(log_file, start=1):
        total_lines += 1
        try:
            for activity, pattern in patterns.items():
                if pattern.search(line):
                    suspicious_activity[activity] += 1
                    suspicious_lines[activity].append((line_number, line.strip()))
        except Exception:
            pass
    return suspicious_activity, total_lines, suspicious_lines

# def save_report(log_file_name, suspicious_activity, total_lines, suspicious_lines):
#     report_file = log_file_name.replace(".log", "_output.txt")
#     with open(report_file, "w") as f:
#         f.write(f"Total lines processed: {total_lines}\n\n")
#         if suspicious_activity:
#             for activity, count in suspicious_activity.items():
#                 f.write(f"{activity}: {count}\n")
#                 f.write(f"{remedies[activity]}\n\n")
#                 f.write("Matching lines:\n")
#                 for line_number, line in suspicious_lines[activity]:
#                     f.write(f"  Line {line_number}: {line}\n")
#                 f.write("\n")
#         else:
#             f.write("No suspicious activity detected.\n")
#     return report_file

def plot_suspicious_activity(suspicious_activity):
    if not suspicious_activity:
        return None

    activities = list(suspicious_activity.keys())
    counts = list(suspicious_activity.values())

    fig, ax = plt.subplots(figsize=(10, 5))
    ax.bar(activities, counts, color="lightblue")
    ax.set_xlabel("Activity Type")
    ax.set_ylabel("Count")
    ax.set_title("Suspicious Activity Detected in Logs")

    return fig

def add_custom_pattern():
    pattern_name = st.text_input("Enter the name of the custom pattern:")
    pattern_regex = st.text_input("Enter the regex for the custom pattern:")
    remedies_name = st.text_input("Enter the Remedies for the custom pattern:")
    if pattern_name and pattern_regex:
        try:
            patterns[pattern_name] = re.compile(pattern_regex, re.IGNORECASE)
            remedies[pattern_name] = remedies_name
            save_patterns()
            st.success("Custom pattern added successfully.")
        except re.error:
            st.error("Invalid regex pattern.")

def create_download_link(df, activity):
    csv = df.to_csv(index=False)
    b64 = base64.b64encode(csv.encode()).decode()  # Encode to base64
    href = f'<a href="data:file/csv;base64,{b64}" download="{activity}_matching_lines.csv">Download</a>'
    return href

def main():
    st.title("Log Analyzer Tool")
    st.sidebar.title("Navigation")
    app_mode = st.sidebar.selectbox("Choose the mode", ["Log Analysis", "Custom Patterns"])

    if app_mode == "Log Analysis":
        # st.header("Log Analysis")
        log_file = st.file_uploader("Upload Log File", type=["log"])
        if log_file:
            # Read the file content
            log_file_content = log_file.read().decode("utf-8").splitlines()

            # Optional time interval filter
            st.subheader("Filter Logs by Time Interval")
            enable_time_filter = st.checkbox("Enable Time Filter", value=False)

            if enable_time_filter:
                # Create two columns for Start Time and End Time
                col1, col2 = st.columns(2)
                
                with col1:
                    start_time = st.time_input("Start Time", value=datetime.strptime("00:00:00", "%H:%M:%S").time())
                
                with col2:
                    end_time = st.time_input("End Time", value=datetime.strptime("23:59:59", "%H:%M:%S").time())

                # Filter logs by time interval if the filter is enabled
                filtered_logs = filter_logs_by_time(log_file_content, start_time, end_time)
                st.write(f"Filtered logs count: {len(filtered_logs)}")
            else:
                # Use all logs if the filter is disabled
                filtered_logs = log_file_content
                st.write(f"Total logs count: {len(filtered_logs)}")

            if filtered_logs:
                suspicious_activity, total_lines, suspicious_lines = analyze_log_file(filtered_logs)
                # report_file = save_report(log_file.name, suspicious_activity, total_lines, suspicious_lines)
                fig = plot_suspicious_activity(suspicious_activity)

                if fig:
                    st.pyplot(fig)
                    # st.success("Graph displayed above.")

                # if suspicious_activity:
                #     st.warning("Suspicious activity detected!")

                st.subheader("Analysis Results")
                st.write(f"Total lines processed: {total_lines}")
                if suspicious_activity:
                    # Create a DataFrame for the table
                    table_data = []
                    for activity, count in suspicious_activity.items():
                        # Create a DataFrame for the matching lines
                        lines_data = []
                        for line_number, line in suspicious_lines[activity]:
                            lines_data.append({"Line Number": line_number, "Line": line})
                        df = pd.DataFrame(lines_data)
                        # Create a download link
                        download_link = create_download_link(df, activity)
                        table_data.append(
                            {
                                "Activity": activity,
                                "Count": count,
                                "Remedy": remedies[activity],
                                "Report": download_link,
                            }
                        )

                    # Convert the table data to a DataFrame
                    table_df = pd.DataFrame(table_data)
                    # Render the table with HTML links
                    st.markdown(
                        table_df.to_html(escape=False, index=False),
                        unsafe_allow_html=True,
                    )
                    # st.success(f"Analysis complete! Report saved to: {report_file}")
                    st.success("Analysis complete!")
                else:
                    st.info("No suspicious activity detected.")
            else:
                st.info("No logs found in the specified time interval.")

    elif app_mode == "Custom Patterns":
        st.header("Custom Pattern Management")
        add_custom_pattern()

if __name__ == "__main__":
    load_patterns()
    main()