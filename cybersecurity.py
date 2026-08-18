import os
import re
import socket
import sqlite3
import hashlib
import subprocess
import requests
import psutil
import pandas as pd
import streamlit as st
import plotly.express as px
import plotly.graph_objects as go

st.set_page_config(page_title="Advanced Linux Security Dashboard", layout="wide", page_icon="🛡️")
st.title("🛡️ Interactive Linux Cyber Security Dashboard & Auto-Fixer")

# -------------------------------------------------------------
# 1. DATABASE & INITIALIZATION (For FIM)
# -------------------------------------------------------------
DB_FILE = 'security_dash.db'

def init_db():
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS fim_baseline
                 (filepath TEXT PRIMARY KEY, hash_value TEXT)''')
    conn.commit()
    conn.close()

init_db()

def get_file_hash(filepath):
    """Calculates SHA-256 hash of a file."""
    hasher = hashlib.sha256()
    try:
        with open(filepath, 'rb') as afile:
            buf = afile.read(65536)
            while len(buf) > 0:
                hasher.update(buf)
                buf = afile.read(65536)
        return hasher.hexdigest()
    except Exception:
        return None

# -------------------------------------------------------------
# 2. REMEDIATION & FIX FUNCTIONS
# -------------------------------------------------------------
def fix_ufw():
    try:
        subprocess.run(["ufw", "--force", "enable"], check=True)
        return True, "UFW Firewall enabled successfully."
    except Exception as e:
        return False, f"Failed to enable UFW: {e}"

def fix_ssh_setting(setting, value):
    try:
        config_path = "/etc/ssh/sshd_config"
        if os.path.exists(config_path):
            with open(config_path, "r") as f:
                content = f.read()

            pattern = rf"^\s*{setting}\s+.*$"
            new_line = f"{setting} {value}"
            if re.search(pattern, content, flags=re.MULTILINE | re.IGNORECASE):
                new_content = re.sub(pattern, new_line, content, flags=re.MULTILINE | re.IGNORECASE)
            else:
                new_content = content + f"\n{new_line}\n"

            with open(config_path, "w") as f:
                f.write(new_content)

            subprocess.run(["systemctl", "restart", "ssh"], check=False)
            subprocess.run(["systemctl", "restart", "sshd"], check=False)
            return True, f"Updated '{setting}' to '{value}' and restarted SSH."
        return False, "sshd_config not found."
    except Exception as e:
        return False, f"Failed to update SSH config: {e}"

def fix_ipv4_forwarding():
    try:
        subprocess.run(["sysctl", "-w", "net.ipv4.ip_forward=0"], check=True)
        return True, "IPv4 forwarding disabled immediately."
    except Exception as e:
        return False, f"Failed to disable IPv4 forwarding: {e}"

def run_apt_upgrade():
    try:
        subprocess.run(["apt-get", "update"], check=True)
        subprocess.run(["apt-get", "upgrade", "-y"], check=True)
        return True, "System security packages updated successfully."
    except Exception as e:
        return False, f"Failed to update packages: {e}"

def terminate_pid(pid):
    try:
        p = psutil.Process(pid)
        p.terminate()
        return True, f"Process PID {pid} ({p.name()}) terminated."
    except Exception as e:
        return False, f"Failed to terminate PID {pid}: {e}"

# -------------------------------------------------------------
# 3. MONITORS & AUDITS
# -------------------------------------------------------------
def get_active_connections():
    connections = []
    for conn in psutil.net_connections(kind='inet'):
        if conn.status == 'LISTEN':
            try:
                process = psutil.Process(conn.pid)
                proc_name = process.name()
                username = process.username()
            except (psutil.NoSuchProcess, psutil.AccessDenied, AttributeError):
                proc_name = "Unknown"
                username = "Unknown"

            connections.append({
                "Port": conn.laddr.port,
                "Process": proc_name,
                "PID": conn.pid,
                "User": username,
                "Type": "TCP" if conn.type == socket.SOCK_STREAM else "UDP"
            })
    return pd.DataFrame(connections)

@st.cache_data(ttl=3600)
def get_geoip(ip):
    try:
        res = requests.get(f"http://ip-api.com/json/{ip}", timeout=2).json()
        if res.get("status") == "success":
            return res.get("lat"), res.get("lon"), res.get("country"), res.get("city")
    except Exception:
        pass
    return None, None, "Unknown", "Unknown"

def parse_failed_logins():
    log_file = "/var/log/auth.log" if os.path.exists("/var/log/auth.log") else "/var/log/secure"
    attacks = []
    if not os.path.exists(log_file):
        return pd.DataFrame(attacks)

    try:
        output = subprocess.check_output(['tail', '-n', '1000', log_file], text=True)
        for line in output.split('\n'):
            if "Failed password" in line:
                ip_match = re.search(r'from ([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)', line)
                if ip_match:
                    ip = ip_match.group(1)
                    user_match = re.search(r'for (invalid user )?(.*?) from', line)
                    user = user_match.group(2) if user_match else "Unknown"
                    attacks.append({"Target User": user, "IP Address": ip})
    except Exception:
        pass

    df = pd.DataFrame(attacks)
    if not df.empty:
        df_grouped = df.groupby(["IP Address", "Target User"]).size().reset_index(name="Attempts")
        lats, lons, countries, cities = [], [], [], []
        for ip in df_grouped["IP Address"]:
            lat, lon, country, city = get_geoip(ip)
            lats.append(lat)
            lons.append(lon)
            countries.append(country)
            cities.append(city)

        df_grouped["Lat"] = lats
        df_grouped["Lon"] = lons
        df_grouped["Country"] = countries
        df_grouped["City"] = cities
        return df_grouped
    return df

def check_security_updates():
    try:
        output = subprocess.check_output(["apt", "list", "--upgradable"], stderr=subprocess.STDOUT, text=True)
        lines = output.strip().split("\n")
        updates = [line for line in lines if "security" in line.lower() or "ubuntu" in line.lower()]
        return len(updates), updates
    except Exception:
        return 0, []

def check_system_configs():
    configs = []
    score_deduction = 0

    # 1. UFW Firewall
    try:
        ufw_status = subprocess.check_output(["ufw", "status"], stderr=subprocess.STDOUT, text=True)
        if "inactive" in ufw_status.lower():
            configs.append({"Check": "UFW Firewall", "Status": "Inactive ❌", "Risk": "High", "Deduction": 20, "FixKey": "ufw"})
            score_deduction += 20
        else:
            configs.append({"Check": "UFW Firewall", "Status": "Active ✅", "Risk": "Low", "Deduction": 0, "FixKey": None})
    except Exception:
        configs.append({"Check": "UFW Firewall", "Status": "Missing / Permission Denied ⚠️", "Risk": "Unknown", "Deduction": 0, "FixKey": None})

    # 2. SSH Root Login
    try:
        if os.path.exists("/etc/ssh/sshd_config"):
            with open("/etc/ssh/sshd_config", "r") as f:
                ssh_config = f.read()
                if re.search(r"^PermitRootLogin\s+yes", ssh_config, re.MULTILINE | re.IGNORECASE):
                    configs.append({"Check": "SSH Root Login", "Status": "Enabled ❌", "Risk": "High", "Deduction": 15, "FixKey": "ssh_root"})
                    score_deduction += 15
                else:
                    configs.append({"Check": "SSH Root Login", "Status": "Disabled / Default ✅", "Risk": "Low", "Deduction": 0, "FixKey": None})
    except Exception:
        pass

    # 3. SSH Password Auth
    try:
        if os.path.exists("/etc/ssh/sshd_config"):
            with open("/etc/ssh/sshd_config", "r") as f:
                ssh_config = f.read()
                if re.search(r"^PasswordAuthentication\s+yes", ssh_config, re.MULTILINE | re.IGNORECASE):
                    configs.append({"Check": "SSH Password Auth", "Status": "Enabled ❌", "Risk": "Medium", "Deduction": 10, "FixKey": "ssh_pass"})
                    score_deduction += 10
                else:
                    configs.append({"Check": "SSH Password Auth", "Status": "Disabled / Default ✅", "Risk": "Low", "Deduction": 0, "FixKey": None})
    except Exception:
        pass

    # 4. IPv4 Forwarding
    try:
        ip_fwd = subprocess.check_output(["sysctl", "net.ipv4.ip_forward"], text=True)
        if "1" in ip_fwd:
            configs.append({"Check": "IPv4 Forwarding", "Status": "Enabled ❌", "Risk": "Medium", "Deduction": 5, "FixKey": "ip_fwd"})
            score_deduction += 5
        else:
            configs.append({"Check": "IPv4 Forwarding", "Status": "Disabled ✅", "Risk": "Low", "Deduction": 0, "FixKey": None})
    except Exception:
        pass

    final_score = max(0, 100 - score_deduction)
    return pd.DataFrame(configs), final_score

# -------------------------------------------------------------
# DASHBOARD LAYOUT & UI
# -------------------------------------------------------------
tab1, tab2, tab3, tab4 = st.tabs([
    "🌐 Active Services & Process Killer",
    "🚨 Intrusion Detection",
    "📂 File Integrity Monitoring",
    "⚙️ Vulnerabilities & Auto-Fixer"
])

# TAB 1: Services & Process Management
with tab1:
    st.header("Listening Services & Direct Process Termination")
    df_ports = get_active_connections()
    if not df_ports.empty:
        col1, col2 = st.columns([2, 1])
        with col1:
            st.dataframe(df_ports.sort_values("Port"), use_container_width=True, height=350)

            st.markdown("### 🛑 Terminate Listening Process")
            col_pid, col_btn = st.columns([2, 1])
            pid_to_kill = col_pid.number_input("Enter Process PID to terminate", min_value=1, step=1)
            if col_btn.button("Kill Process", type="primary"):
                success, msg = terminate_pid(int(pid_to_kill))
                if success:
                    st.success(msg)
                    st.rerun()
                else:
                    st.error(msg)
        with col2:
            fig = px.pie(df_ports, names="Process", title="Processes Holding Ports Open")
            st.plotly_chart(fig, use_container_width=True)
    else:
        st.warning("No listening ports found, or missing root privileges.")

# TAB 2: Intrusion Detection
with tab2:
    st.header("SSH Brute-Force Attempts & Geolocation")
    df_attacks = parse_failed_logins()

    if not df_attacks.empty:
        col_map, col_data = st.columns([2, 1])
        with col_map:
            df_map = df_attacks.dropna(subset=["Lat", "Lon"])
            if not df_map.empty:
                fig_map = px.scatter_geo(
                    df_map, lat="Lat", lon="Lon", color="Attempts",
                    hover_name="IP Address", hover_data=["City", "Country", "Target User"],
                    size="Attempts", projection="natural earth",
                    title="Geographic Origin of Failed Logins"
                )
                st.plotly_chart(fig_map, use_container_width=True)
            else:
                st.info("No geolocatable attacks found.")

        with col_data:
            st.dataframe(df_attacks[["IP Address", "Target User", "Attempts", "Country"]].sort_values("Attempts", ascending=False), use_container_width=True)
    else:
        st.success("No failed login attempts found in recent logs.")

# TAB 3: File Integrity Monitoring
with tab3:
    st.header("File Integrity Baseline Management")
    critical_files = [
        "/etc/passwd", "/etc/shadow", "/etc/sudoers",
        "/etc/ssh/sshd_config", "/etc/crontab"
    ]

    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()

    if st.button("Set / Reset Baseline Hash", type="primary"):
        c.execute("DELETE FROM fim_baseline")
        for f in critical_files:
            file_hash = get_file_hash(f)
            if file_hash:
                c.execute("INSERT INTO fim_baseline (filepath, hash_value) VALUES (?, ?)", (f, file_hash))
        conn.commit()
        st.success("Security baseline updated!")

    st.subheader("Current Status")
    fim_results = []
    for f in critical_files:
        current_hash = get_file_hash(f)
        c.execute("SELECT hash_value FROM fim_baseline WHERE filepath = ?", (f,))
        row = c.fetchone()

        status = "Unknown"
        if not current_hash:
            status = "Missing/Unreadable"
        elif not row:
            status = "Not in Baseline ⚠️"
        elif current_hash == row[0]:
            status = "Unchanged ✅"
        else:
            status = "MODIFIED ❌"

        fim_results.append({"File": f, "Status": status, "Current SHA-256": current_hash[:16]+"..." if current_hash else "N/A"})

    st.dataframe(pd.DataFrame(fim_results), use_container_width=True)
    conn.close()

# TAB 4: Vulnerabilities, Score & Auto-Fixing
with tab4:
    st.header("Security Score Audit & 1-Click Fixes")

    col_vuln, col_score = st.columns(2)

    with col_vuln:
        st.subheader("Package Vulnerabilities")
        vuln_count, vuln_details = check_security_updates()
        if vuln_count > 0:
            st.error(f"Found {vuln_count} pending security updates!")
            if st.button("🔧 Apply Security Updates (`apt upgrade`)", type="primary"):
                with st.spinner("Upgrading security packages..."):
                    success, msg = run_apt_upgrade()
                    if success:
                        st.success(msg)
                        st.rerun()
                    else:
                        st.error(msg)
            with st.expander("View Vulnerable Packages"):
                for pkg in vuln_details:
                    st.write(pkg)
        else:
            st.success("System packages are fully up to date.")

    with col_score:
        st.subheader("Security Score")
        df_configs, sys_score = check_system_configs()

        fig_score = go.Figure(go.Indicator(
            mode="gauge+number",
            value=sys_score,
            title={'text': "Security Rating", 'font': {'size': 20}},
            gauge={
                'axis': {'range': [0, 100]},
                'bar': {'color': "black"},
                'steps': [
                    {'range': [0, 50], 'color': "#EF553B"},
                    {'range': [50, 80], 'color': "#FFA15A"},
                    {'range': [80, 100], 'color': "#00CC96"}
                ]
            }
        ))
        st.plotly_chart(fig_score, use_container_width=True)

    st.subheader("Audit Recommendations & Quick Actions")
    if not df_configs.empty:
        for idx, row in df_configs.iterrows():
            col_check, col_status, col_act = st.columns([2, 2, 2])
            col_check.write(f"**{row['Check']}**")
            col_status.write(row['Status'])

            if row['FixKey'] == 'ufw':
                if col_act.button("Fix: Enable UFW", key=f"fix_{idx}"):
                    ok, msg = fix_ufw()
                    if ok: st.success(msg); st.rerun()
                    else: st.error(msg)
            elif row['FixKey'] == 'ssh_root':
                if col_act.button("Fix: Disable SSH Root Login", key=f"fix_{idx}"):
                    ok, msg = fix_ssh_setting("PermitRootLogin", "no")
                    if ok: st.success(msg); st.rerun()
                    else: st.error(msg)
            elif row['FixKey'] == 'ssh_pass':
                if col_act.button("Fix: Disable SSH Password Auth", key=f"fix_{idx}"):
                    ok, msg = fix_ssh_setting("PasswordAuthentication", "no")
                    if ok: st.success(msg); st.rerun()
                    else: st.error(msg)
            elif row['FixKey'] == 'ip_fwd':
                if col_act.button("Fix: Disable IPv4 Forwarding", key=f"fix_{idx}"):
                    ok, msg = fix_ipv4_forwarding()
                    if ok: st.success(msg); st.rerun()
                    else: st.error(msg)
