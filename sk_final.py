import os
import json
import base64
import requests
import uuid
from datetime import datetime, timedelta
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
import pytz # Requires: pip install pytz

# --- CONFIGURATION ---
BASE_URL = "https://skapp.top" # Fallback

# --- KEYS (DO NOT CHANGE) ---
KEY = bytes.fromhex("6c326c356b4237784335715031724b31")
IV = bytes.fromhex("70314b356e50377542386848316c3139")

# Lookup Table
LOOKUP_TABLE_D = (
    "\u0000\u0001\u0002\u0003\u0004\u0005\u0006\u0007\x08\t\n\u000b\u000c\r\u000e\u000f"
    "\u0010\u0011\u0012\u0013\u0014\u0015\u0016\u0017\x18\x19\x1a\u001b\u001c\u001d\u001e\u001f"
    " !\"#$%&'()*+,-./0123456789:;<=>?@EGMNKABUVCDYHLIFPOZQSRWTXJ[\\]^_`egmnkabuvcdyhlifpozqsrwtxj{|}~\x7f"
)

# --- DECRYPTION ENGINE ---
def custom_to_standard_base64(enc_string):
    res = []
    for char in enc_string:
        idx = ord(char)
        if idx < len(LOOKUP_TABLE_D):
            res.append(LOOKUP_TABLE_D[idx])
        else:
            res.append(char)
    return "".join(res)

def decrypt_sk_live(encrypted_text):
    if not encrypted_text: return None
    try:
        standard_b64 = custom_to_standard_base64(encrypted_text)
        decoded_bytes = base64.b64decode(standard_b64)
        decoded_str = decoded_bytes.decode('utf-8')
        reversed_str = decoded_str[::-1]
        ciphertext = base64.b64decode(reversed_str)
        cipher = AES.new(KEY, AES.MODE_CBC, IV)
        decrypted_bytes = unpad(cipher.decrypt(ciphertext), AES.block_size)
        return decrypted_bytes.decode('utf-8')
    except: return None

# --- FIREBASE LOGIC ---
def get_base_url(session):
    print("   ☁️  Contacting Firebase for latest URL...")
    try:
        url = "https://firebaseremoteconfig.googleapis.com/v1/projects/330162934410/namespaces/firebase:fetch"
        fake_id = uuid.uuid4().hex 
        
        payload = {
            "appInstanceId": fake_id,
            "appInstanceIdToken": "",
            "appId": "1:330162934410:android:0d81c4732e3d206d6cd373",
            "countryCode": "US",
            "languageCode": "en-US",
            "platformVersion": "30",
            "timeZone": "UTC",
            "appVersion": "5.0",
            "appBuild": "50",
            "packageName": "com.live.sktechtv",
            "sdkVersion": "22.1.0",
            "analyticsUserProperties": {}
        }
        
        headers = {
            "X-Goog-Api-Key": "AIzaSyClGjK1EBL-ZLbCoep1z5QSmwMyHshimSk",
            "X-Android-Package": "com.live.sktechtv",
            "Content-Type": "application/json",
            "Accept": "application/json",
            "User-Agent": "okhttp/5.0.0-alpha.12"
        }
        
        # Use session for speed
        resp = session.post(url, json=payload, headers=headers, timeout=10)
        
        if resp.status_code == 200:
            data = resp.json()
            api_url = data.get("entries", {}).get("api_url")
            if api_url: 
                clean_url = api_url.rstrip("/")
                print(f"   ✅ Firebase returned: {clean_url}")
                return clean_url
    except Exception as e:
        print(f"   ⚠️ Firebase Error: {e}")
        
    return BASE_URL

# --- TIME & STATUS UTILS ---
def get_event_status_and_time(date_str, time_str):
    """
    Parses "23/01/2026" and "13:30:00" -> IST Time string + Status
    """
    try:
        if not date_str or not time_str:
            return "", ""
            
        # Parse App Time (Usually UTC or local to server)
        # Assuming format DD/MM/YYYY HH:mm:ss
        dt_str = f"{date_str} {time_str}"
        dt_obj = datetime.strptime(dt_str, "%d/%m/%Y %H:%M:%S")
        
        # Convert to IST
        utc_zone = pytz.timezone('UTC') # Assuming app dates are UTC
        ist_zone = pytz.timezone('Asia/Kolkata')
        
        # If app time is naive, localize to UTC first (Assumption)
        dt_utc = utc_zone.localize(dt_obj)
        dt_ist = dt_utc.astimezone(ist_zone)
        
        # Format for display
        ist_display = dt_ist.strftime("%d %b %I:%M %p")
        
        # Determine Status
        now_ist = datetime.now(ist_zone)
        
        if now_ist < dt_ist:
            status = "Upcoming"
        elif now_ist > dt_ist + timedelta(hours=8): # Assume match < 8 hours
            status = "Recent"
        else:
            status = "🔴 Live"
            
        return status, ist_display
    except:
        return "", ""

# --- DEEP RESOLVER ---
def fetch_stream_links(session, slug, base_url):
    valid_links = []
    try:
        target_url = slug if slug.startswith("http") else f"{base_url}/{slug}"
        # print(f"     ↳ Resolving: {target_url}") # Commented to reduce log spam
        
        resp = session.get(target_url, timeout=10) # Fast timeout
        if resp.status_code == 200:
            decrypted_json = decrypt_sk_live(resp.text.strip())
            
            if decrypted_json:
                streams = json.loads(decrypted_json)
                if isinstance(streams, list):
                    for stream in streams:
                        link = stream.get("link")
                        name = stream.get("name") or stream.get("title") or "Server"
                        drm = stream.get("api")
                        
                        if link and "http" in link:
                            valid_links.append({
                                "title": name,
                                "link": link,
                                "drm": drm
                            })
    except: pass
    return valid_links

# --- MAIN ENGINE ---
def main():
    print("🚀 Starting SK Live Scraper (Optimized Mode)...")
    
    # Use a Session for connection pooling (Faster)
    session = requests.Session()
    session.headers.update({
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
    })
    
    # 1. Get Host
    current_base_url = get_base_url(session)
    events_url = f"{current_base_url}/events.txt"
    
    final_playlist = []
    
    try:
        # 2. Fetch Main List
        print(f"📡 Fetching Events: {events_url}")
        resp = session.get(events_url, timeout=20)
        
        if resp.status_code == 200:
            decrypted_events = decrypt_sk_live(resp.text.strip())
            
            if decrypted_events:
                wrapper_list = json.loads(decrypted_events)
                print(f"🔓 Processing {len(wrapper_list)} events...")
                
                for wrapper in wrapper_list:
                    inner_enc = wrapper.get("event")
                    if not inner_enc: continue
                    try: item = json.loads(inner_enc)
                    except: continue

                    # 3. Filter Logic
                    cat = item.get("category", "").lower()
                    name = item.get("eventName", "").lower()
                    
                    if "cricket" in cat or "cricket" in name or "t20" in name or "match" in name:
                        
                        # Data Extraction
                        team_a = item.get('teamAName', '')
                        team_b = item.get('teamBName', '')
                        event_name = item.get('eventName', '')
                        
                        if team_a and team_b:
                            match_title = f"{team_a} vs {team_b}"
                        else:
                            match_title = event_name
                            
                        slug_link = item.get("links")
                        logo = item.get("eventLogo", "")
                        
                        # Time & Status
                        date_raw = item.get("date")
                        time_raw = item.get("time")
                        status, ist_time = get_event_status_and_time(date_raw, time_raw)
                        
                        # Group Title Construction (Cricz Style)
                        if ist_time:
                            group_title = f"{status} | {match_title} [{ist_time}]"
                        else:
                            group_title = f"{status} | {match_title}"
                        
                        # 4. Fetch Links
                        if slug_link:
                            stream_list = fetch_stream_links(session, slug_link, current_base_url)
                            
                            if stream_list:
                                print(f"   🏏 {group_title} ({len(stream_list)} Links)")
                                
                                for stream in stream_list:
                                    srv_name = stream['title']
                                    srv_link = stream['link']
                                    drm_info = stream['drm']
                                    
                                    # M3U Entry Construction
                                    entry = f'#EXTINF:-1 tvg-logo="{logo}" group-title="{group_title}", {match_title} ({srv_name})\n'
                                    
                                    if drm_info:
                                        entry += '#KODIPROP:inputstream.adaptive.license_type=clearkey\n'
                                        entry += f'#KODIPROP:inputstream.adaptive.license_key={drm_info}\n'
                                    
                                    # Append Original Link
                                    entry += f"{srv_link}\n"
                                    
                                    final_playlist.append(entry)

    except Exception as e:
        print(f"❌ Critical Error: {e}")

    # 5. Write to File (Always Overwrite)
    try:
        with open("playlist.m3u", "w", encoding="utf-8") as f:
            f.write("#EXTM3U\n")
            f.write(f"# Updated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"# Total Channels: {len(final_playlist)}\n\n")
            
            if final_playlist:
                for entry in final_playlist:
                    f.write(entry)
                print(f"\n🎉 SUCCESS! Playlist generated with {len(final_playlist)} streams.")
            else:
                f.write(f"# No Matches Found\n")
                print(f"\n⚠️ No matches found (Playlist Cleared).")
                
    except Exception as e:
        print(f"❌ File Write Error: {e}")

if __name__ == "__main__":
    main()

