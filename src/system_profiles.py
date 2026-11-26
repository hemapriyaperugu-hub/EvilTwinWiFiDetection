import locale
import re
import subprocess
import sys
import urllib.error
import urllib.request

if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass


def _decode_bytes(raw_bytes):
    if not raw_bytes:
        return ""
    for enc in ("utf-8", locale.getpreferredencoding(False) or "cp1252"):
        try:
            return raw_bytes.decode(enc)
        except UnicodeDecodeError:
            continue
    return raw_bytes.decode("utf-8", errors="replace")


def get_saved_windows_profiles():
    """
    Retrieves the list of saved Wi-Fi profiles configured in Windows.
    Uses 'netsh wlan show profiles'.
    Returns a dict mapping SSID -> profile info dictionary.
    """
    profiles = {}
    try:
        res = subprocess.run(
            ["netsh", "wlan", "show", "profiles"],
            capture_output=True,
            timeout=5
        )
        if res.returncode != 0:
            return profiles

        stdout_text = _decode_bytes(res.stdout)
        for line in stdout_text.splitlines():
            line = line.strip()
            m = re.match(r"^(?:All User Profile|User Profile)\s*:\s*(.*)$", line, re.IGNORECASE)
            if m:
                pname = m.group(1).strip()
                if pname:
                    profiles[pname] = {"name": pname}

    except Exception:
        pass

    return profiles


def get_profile_security_details(profile_name):
    """
    Retrieves security details (Authentication, Encryption, PMF) for a specific profile.
    Uses 'netsh wlan show profile name="<profile_name>"'.
    """
    details = {
        "Authentication": "Unavailable",
        "Authentications": [],
        "Cipher": "Unavailable",
        "Ciphers": [],
        "PMF_Enabled": False
    }
    if not profile_name:
        return details

    try:
        res = subprocess.run(
            ["netsh", "wlan", "show", "profile", f"name={profile_name}"],
            capture_output=True,
            timeout=5
        )
        if res.returncode != 0:
            return details

        stdout_text = _decode_bytes(res.stdout)
        auths = []
        ciphers = []
        for line in stdout_text.splitlines():
            line = line.strip()
            low = line.lower()
            if low.startswith("authentication"):
                parts = line.split(":", 1)
                if len(parts) > 1 and parts[1].strip():
                    auths.append(parts[1].strip())
            elif low.startswith("cipher"):
                parts = line.split(":", 1)
                if len(parts) > 1 and parts[1].strip():
                    ciphers.append(parts[1].strip())
            elif "pmf" in low and ("true" in low or "enabled" in low):
                details["PMF_Enabled"] = True

        if auths:
            details["Authentications"] = auths
            has_wpa2 = any("wpa2" in a.lower() for a in auths)
            has_wpa3 = any("wpa3" in a.lower() for a in auths)
            if has_wpa2 and has_wpa3:
                details["Authentication"] = "WPA2/WPA3-Personal"
            else:
                details["Authentication"] = auths[0]
            if has_wpa3:
                details["PMF_Enabled"] = True
        if ciphers:
            details["Ciphers"] = ciphers
            details["Cipher"] = ciphers[0]

    except Exception:
        pass

    return details


def get_active_wifi_interface():
    """
    Inspects current Wi-Fi connection status using 'netsh wlan show interfaces'.
    Returns connected SSID, BSSID, Channel, Band, Signal, Radio, Authentication, Cipher.
    """
    status = {
        "State": "disconnected",
        "SSID": "",
        "BSSID": "",
        "Channel": None,
        "Band": "",
        "Signal": None,
        "Radio": "",
        "Authentication": "",
        "Cipher": "",
        "Profile": ""
    }
    try:
        res = subprocess.run(
            ["netsh", "wlan", "show", "interfaces"],
            capture_output=True,
            timeout=5
        )
        if res.returncode != 0:
            return status

        stdout_text = _decode_bytes(res.stdout)
        for line in stdout_text.splitlines():
            line = line.strip()
            low = line.lower()
            if low.startswith("state"):
                parts = line.split(":", 1)
                if len(parts) > 1:
                    status["State"] = parts[1].strip().lower()
            elif low.startswith("ssid") and not low.startswith("ap bssid"):
                parts = line.split(":", 1)
                if len(parts) > 1:
                    status["SSID"] = parts[1].strip()
            elif low.startswith("ap bssid") or low.startswith("bssid"):
                parts = line.split(":", 1)
                if len(parts) > 1:
                    status["BSSID"] = parts[1].strip().lower().replace("-", ":")
            elif low.startswith("channel"):
                m = re.search(r"(\d+)", line)
                if m:
                    status["Channel"] = int(m.group(1))
            elif low.startswith("band"):
                parts = line.split(":", 1)
                if len(parts) > 1:
                    status["Band"] = parts[1].strip()
            elif low.startswith("signal"):
                m = re.search(r"(\d+)\s*%", line)
                if m:
                    status["Signal"] = int(m.group(1))
            elif low.startswith("radio type"):
                parts = line.split(":", 1)
                if len(parts) > 1:
                    status["Radio"] = parts[1].strip()
            elif low.startswith("authentication"):
                parts = line.split(":", 1)
                if len(parts) > 1:
                    status["Authentication"] = parts[1].strip()
            elif low.startswith("cipher"):
                parts = line.split(":", 1)
                if len(parts) > 1:
                    status["Cipher"] = parts[1].strip()
            elif low.startswith("profile"):
                parts = line.split(":", 1)
                if len(parts) > 1:
                    status["Profile"] = parts[1].strip()

    except Exception:
        pass

    return status


def get_default_gateway_and_ip():
    """
    Retrieves current IPv4 Address, Default Gateway IP, and Gateway MAC address (via ARP).
    """
    info = {
        "IP": "",
        "Gateway_IP": "",
        "Gateway_MAC": "",
        "DNS_Servers": []
    }
    try:
        res = subprocess.run(
            ["ipconfig", "/all"],
            capture_output=True,
            timeout=5
        )
        stdout_text = _decode_bytes(res.stdout)
        in_wifi_adapter = False
        collecting_gateway = False
        for line in stdout_text.splitlines():
            line_strip = line.strip()
            if "Wireless LAN adapter" in line:
                in_wifi_adapter = True
            elif "adapter" in line_strip and not line_strip.startswith("Wireless"):
                in_wifi_adapter = False
                collecting_gateway = False

            if in_wifi_adapter:
                if "IPv4 Address" in line:
                    m = re.search(r"(\d+\.\d+\.\d+\.\d+)", line)
                    if m:
                        info["IP"] = m.group(1)
                elif "Default Gateway" in line:
                    collecting_gateway = True
                    m = re.search(r"(\d+\.\d+\.\d+\.\d+)", line)
                    if m:
                        info["Gateway_IP"] = m.group(1)
                elif collecting_gateway:
                    if line_strip and ":" not in line_strip:
                        m = re.search(r"(\d+\.\d+\.\d+\.\d+)", line_strip)
                        if m and not info["Gateway_IP"]:
                            info["Gateway_IP"] = m.group(1)
                    elif ":" in line_strip:
                        collecting_gateway = False

                if "DNS Servers" in line:
                    m = re.search(r"(\d+\.\d+\.\d+\.\d+)", line)
                    if m:
                        info["DNS_Servers"].append(m.group(1))

        if info["Gateway_IP"]:
            arp_res = subprocess.run(
                ["arp", "-a", info["Gateway_IP"]],
                capture_output=True,
                timeout=5
            )
            arp_text = _decode_bytes(arp_res.stdout)
            for l in arp_text.splitlines():
                if info["Gateway_IP"] in l:
                    m_mac = re.search(
                        r"([0-9a-fA-F]{2}[:-][0-9a-fA-F]{2}[:-][0-9a-fA-F]{2}[:-][0-9a-fA-F]{2}[:-][0-9a-fA-F]{2}[:-][0-9a-fA-F]{2})",
                        l
                    )
                    if m_mac:
                        info["Gateway_MAC"] = m_mac.group(1).lower().replace("-", ":")
                        break

    except Exception:
        pass

    return info


def check_captive_portal(timeout=3):
    """
    Checks if connected network is intercepted by an unexpected captive portal.
    Uses standard HTTP 204 probe (connectivitycheck.gstatic.com/generate_204).
    Returns (is_captive_portal: bool, message: str).
    """
    test_url = "http://connectivitycheck.gstatic.com/generate_204"
    try:
        req = urllib.request.Request(
            test_url,
            headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"}
        )
        with urllib.request.urlopen(req, timeout=timeout) as response:
            code = response.getcode()
            if code == 204:
                return False, "Direct Internet connectivity verified (HTTP 204 No Content)."
            elif code in [301, 302, 307]:
                return True, f"Captive portal detected: HTTP redirect to {response.headers.get('Location', 'login page')}."
            else:
                body = response.read(512).decode("utf-8", errors="ignore").lower()
                if "login" in body or "portal" in body or "<html" in body:
                    return True, "Captive portal detected: HTTP 204 request returned HTML login page."
                return False, f"HTTP status {code} received."
    except urllib.error.HTTPError as e:
        if e.code in [301, 302, 307]:
            return True, f"Captive portal detected: HTTP {e.code} redirect."
        return False, f"HTTP error {e.code} during probe."
    except Exception as e:
        return False, f"Probe could not reach test endpoint ({e}). (Offline or local network only)."


if __name__ == "__main__":
    print("=== Saved Profiles ===")
    profs = get_saved_windows_profiles()
    print(f"Found {len(profs)} profiles:", list(profs.keys())[:10])
    print("\n=== Active Interface ===")
    print(get_active_wifi_interface())
    print("\n=== Gateway & IP ===")
    print(get_default_gateway_and_ip())
    print("\n=== Captive Portal Check ===")
    print(check_captive_portal())
