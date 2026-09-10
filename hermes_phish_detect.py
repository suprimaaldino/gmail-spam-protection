#!/usr/bin/env python3
"""Gmail Phishing/Spam Detector — IMAP-based (Multi-account via env vars)"""
import imaplib, email, re, sys, time, os, urllib.request, json
from datetime import datetime, timezone, timedelta
from urllib.parse import urlparse

# Telegram notification (optional) — SUCCESS ONLY, no fail notifications
TG_BOT_TOKEN = os.environ.get("TG_BOT_TOKEN", "")
TG_CHAT_ID = os.environ.get("TG_CHAT_ID", "5100924103")
TG_RUN_ON_COMMAND = os.environ.get("TG_RUN_ON_COMMAND", "1") == "1"  # allow /scan via Telegram

def tg_send(text):
    if not TG_BOT_TOKEN: return
    url = f"https://api.telegram.org/bot{TG_BOT_TOKEN}/sendMessage"
    data = json.dumps({"chat_id": TG_CHAT_ID, "text": text, "parse_mode": "HTML"}).encode()
    req = urllib.request.Request(url, data=data, headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            r.read()
    except Exception: pass

def tg_get_updates(offset=0):
    """Poll for Telegram commands (for Railway direct Telegram integration)"""
    if not TG_BOT_TOKEN: return []
    url = f"https://api.telegram.org/bot{TG_BOT_TOKEN}/getUpdates?offset={offset}&timeout=5"
    try:
        with urllib.request.urlopen(url, timeout=10) as r:
            data = json.loads(r.read().decode())
            return data.get("result", [])
    except Exception: return []

def handle_telegram_command(command, chat_id):
    """Handle /scan command from Telegram"""
    if command == "scan":
        tg_send(f"🔄 Starting scan for {len(ACCOUNTS)} account(s)...", chat_id)
        all_flagged = []
        scan_failed = False
        for acc in ACCOUNTS:
            try:
                result = scan_account(acc['user'], acc['pass'])
                if result is None:
                    scan_failed = True
                    continue
                all_flagged.extend(result)
            except Exception as e:
                print(f"[!] Error scanning {acc['user']}: {e}")
                scan_failed = True
            time.sleep(DELAY_BETWEEN_ACCOUNTS)
        if scan_failed:
            tg_send("❌ Scan failed — check credentials/connectivity.", chat_id)
        elif all_flagged:
            lines = [f"⚠️ <b>PHISHING DETECTED</b>", f"Total flagged: {len(all_flagged)}", f"Accounts scanned: {len(ACCOUNTS)}", ""]
            for i, m in enumerate(sorted(all_flagged, key=lambda x: x['score'], reverse=True)[:5], 1):
                lines.append(f"#{i} [{m['score']}⚠]")
                lines.append(f"From: {m['from']}")
                lines.append(f"Subject: {m['subject'][:60]}")
                if m['indicators']:
                    lines.append(f"Indicators: {', '.join(m['indicators'][:3])}")
                lines.append("")
            lines.append("Automatically moved to Spam.")
            tg_send("\n".join(lines), chat_id)
        else:
            tg_send("✅ Gmail scan clean — 0 phishing detected.", chat_id)
        return True
    return False

# Build accounts from env vars (GMAIL_USER_1, GMAIL_PASS_1, etc.)
ACCOUNTS = []
i = 1
while True:
    user = os.environ.get(f"GMAIL_USER_{i}")
    pwd = os.environ.get(f"GMAIL_PASS_{i}")
    if not user or not pwd: break
    ACCOUNTS.append({"user": user, "pass": pwd})
    i += 1

# Fallback to argv if env not set
if not ACCOUNTS:
    ACCOUNTS.append({
        "user": sys.argv[1] if len(sys.argv) > 1 else "aldinoaja@gmail.com",
        "pass": sys.argv[2] if len(sys.argv) > 2 else "",
    })

MAX_EMAILS = 20
SCAN_HOURS = 48
DELAY_BETWEEN_ACCOUNTS = 2
IMAP_TIMEOUT = 30

PHISH_KEYWORDS = [
    r'\b(verify|verification|confirm|confirmation|account\s*suspended|suspended\s*account)\b',
    r'\b(urgent|immediately|action\s*required|within\s*\d+\s*hours?)\b',
    r'\b(unauthorized|login\s*(attempt|alert|notification)|suspicious\s*activity)\b',
    r'\b(update\s*your|renew\s*your|expir(e|ing)|security\s*alert)\b',
    r'\b(click\s*the\s*link|below\s*to|sign\s*in\s*to|reset\s*password)\b',
]
SUSPICIOUS_TLDS = ['.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top', '.club', '.ru', '.pw', '.cc']
LEGIT_GOOGLE_DOMAINS = {
    'google.com', 'google.co.id', 'googleapis.com', 'googleusercontent.com',
    'gstatic.com', 'googlevideo.com', 'googleapis.cn', 'google.com.cn',
    'accounts.google.com', 'myaccount.google.com', 'support.google.com',
    'cloud.google.com', 'console.cloud.google.com', 'drive.google.com',
    'mail.google.com', 'docs.google.com', 'sheets.google.com',
    'ssl.google.com', 'lh3.googleusercontent.com', 'www.google.com',
    'fonts.googleapis.com', 'fonts.gstatic.com',
}
TRUSTED_DRIVE_SENDERS = {
    'drive-shares-dm-noreply@google.com',
    'noreply@accounts.google.com',
    'noreply-accounts@google.com',
    'drive.google.com',
}
BRAND_DOMAINS = {
    'allobank': ['allobank.co.id', 'allobank.com'],
    'bri': ['bri.co.id', 'bri.com'],
    'bca': ['bca.co.id', 'bca.com'],
    'mandiri': ['mandiri.co.id', 'mandiri.com'],
    'bni': ['bni.co.id', 'bni.com'],
    'permata': ['permata.co.id', 'permata.com'],
    'dana': ['dana.id'], 'ovo': ['ovo.id'],
    'gopay': ['gopay.com'], 'shopeepay': ['shopeepay.com'],
}

def suspicious_url(text):
    urls = re.findall(r'https?://[^\s<>"\']+', text)
    results = []
    for u in urls:
        host = urlparse(u).netloc.lower().split(':')[0]
        if host in LEGIT_GOOGLE_DOMAINS or host.endswith('.googleusercontent.com'):
            continue
        reasons = []
        if re.match(r'^\d{1,3}(\.\d{1,3}){3}$', host): reasons.append('IP-as-domain')
        for tld in SUSPICIOUS_TLDS:
            if host.endswith(tld): reasons.append(f'suspicious-TLD:{tld}')
        for legit in ['google', 'apple', 'amazon', 'microsoft', 'paypal', 'bank', 'dropbox']:
            if legit in host and host != f'{legit}.com' and host != f'www.{legit}.com':
                reasons.append(f'spoofed-{legit}')
        if any(s in host for s in ['bit.ly', 'tinyurl', 'ow.ly', 't.co']): reasons.append('short-url')
        if reasons: results.append({'url': u, 'reasons': reasons})
    return results

def check_phishing(msg):
    indicators = []
    score = 0
    text = msg.get('body', msg.get('payload', ''))
    subject = msg.get('subject', '')
    sender = msg.get('from', '')
    content_type = msg.get('content_type', '')
    body_text = msg.get('body_text', '')
    for kw in PHISH_KEYWORDS:
        if re.search(kw, text, re.IGNORECASE):
            score += 1
            indicators.append(f'keyword:{kw[:40]}')
    bad_urls = suspicious_url(text)
    if bad_urls:
        score += len(bad_urls)
        for b in bad_urls:
            indicators.append(f'url:{b["url"][:50]} ({", ".join(b["reasons"])})')
    display_match = re.match(r'(.+?)\s*<([^>]+)>', sender)
    if display_match:
        display_name = display_match.group(1).lower().strip()
        email_addr = display_match.group(2).lower()
        if email_addr not in TRUSTED_DRIVE_SENDERS:
            for brand, legit_domains in BRAND_DOMAINS.items():
                if brand in display_name:
                    if brand not in email_addr and not any(ld in email_addr for ld in legit_domains):
                        score += 3
                        indicators.append(f'brand-spoof:{brand} in display, not in {email_addr}')
    domain = sender.split('@')[-1].split('>')[0].strip().lower()
    if domain and not domain.endswith(('.com', '.co.id', '.org', '.net', '.go.id', '.ac.id')):
        if not re.match(r'^[a-z0-9.-]+\.[a-z]{2,}$', domain):
            score += 1
            indicators.append(f'suspicious-domain:{domain}')
    if not subject.strip():
        score += 1
        indicators.append('no-subject')
    if content_type == 'text/html' and not body_text:
        score += 0.5
    return score, indicators

def fetch_recent(mail):
    cutoff = datetime.now(timezone.utc) - timedelta(hours=SCAN_HOURS)
    status, data = mail.search(None, 'ALL')
    if status != 'OK': return []
    ids = data[0].split()
    messages = []
    for mid in ids[-MAX_EMAILS:]:
        status, msg_data = mail.fetch(mid, '(RFC822)')
        if status != 'OK': continue
        raw = msg_data[0][1]
        msg = email.message_from_bytes(raw)
        subject_parts = email.header.decode_header(msg.get('Subject', ''))
        subject = ''.join(p.decode(enc or 'utf-8') if isinstance(p, bytes) else p for p, enc in subject_parts)
        from_parts = email.header.decode_header(msg.get('From', ''))
        frm = ''.join(p.decode(enc or 'utf-8') if isinstance(p, bytes) else p for p, enc in from_parts)
        try:
            msg_date = email.utils.parsedate_to_datetime(msg.get('Date', ''))
            if msg_date.tzinfo is None: msg_date = msg_date.replace(tzinfo=timezone.utc)
            else: msg_date = msg_date.astimezone(timezone.utc)
        except Exception: msg_date = cutoff
        if msg_date < cutoff: continue
        body = ''
        body_text = ''
        content_type = msg.get_content_type()
        if msg.is_multipart():
            for part in msg.walk():
                ct = part.get_content_type()
                if ct in ('text/plain', 'text/html'):
                    try:
                        b = part.get_payload(decode=True)
                        if b:
                            decoded = b.decode(part.get_content_charset() or 'utf-8', errors='replace')
                            if ct == 'text/plain' and not body_text: body_text = decoded
                            if not body: body = decoded
                    except Exception: pass
        else:
            try:
                body = msg.get_payload(decode=True).decode(msg.get_content_charset() or 'utf-8', errors='replace')
                body_text = body
            except Exception: pass
        messages.append({'id': mid.decode(), 'from': frm, 'subject': subject, 'date': msg.get('Date', ''),
                         'content_type': content_type, 'body': body[:2000], 'body_text': body_text[:2000]})
    return messages

def scan_account(user, app_pass):
    for attempt in range(3):
        try:
            mail = imaplib.IMAP4_SSL('imap.gmail.com', 993, timeout=IMAP_TIMEOUT)
            mail.login(user, app_pass)
            break
        except Exception as e:
            if attempt == 2:
                print(f"[!] LOGIN FAILED for {user} after 3 attempts: {e}")
                return None
            print(f"[!] Login attempt {attempt+1} failed, retrying in 5s...")
            time.sleep(5)
    mail.select('INBOX')
    status, data = mail.status('INBOX', '(MESSAGES)')
    total = int(data[0].decode().split('MESSAGES ')[1].split(')')[0]) if data[0] else 0
    print(f"[*] Inbox: {total} total messages")
    messages = fetch_recent(mail)
    if not messages:
        print(f"[*] No recent messages for {user}.")
        mail.logout()
        return []
    print(f"[*] Scanning {len(messages)} recent messages...")
    flagged = []
    for msg in messages:
        score, indicators = check_phishing(msg)
        msg['score'] = score
        msg['indicators'] = indicators
        if score >= 3: flagged.append(msg)
    print(f"  Flagged: {len(flagged)}/{len(messages)}")
    if flagged:
        for m in sorted(flagged, key=lambda x: x['score'], reverse=True):
            print(f"  ⚠ [{m['score']}] {m['from']} — {m['subject'][:60]}")
            for ind in m['indicators']: print(f"      • {ind}")
            mail.copy(m['id'], '[Gmail]/Spam')
            mail.store(m['id'], '+FLAGS', r'(\Seen)')
            try: mail.store(m['id'], '+X-GM-LABELS', r'(\Phishing)')
            except Exception: pass
        mail.expunge()
        print(f"  [✓] {len(flagged)} moved to Spam.")
    mail.logout()
    return flagged

def main():
    all_flagged = []
    scan_failed = False
    for acc in ACCOUNTS:
        try:
            result = scan_account(acc['user'], acc['pass'])
            if result is None:
                scan_failed = True
                continue
            all_flagged.extend(result)
        except Exception as e:
            print(f"[!] Error scanning {acc['user']}: {e}")
            scan_failed = True
        time.sleep(DELAY_BETWEEN_ACCOUNTS)
    print(f"\n{'=' * 80}")
    print(f"  TOTAL: {len(all_flagged)} phishing email(s) flagged across all accounts.")
    print(f"{'=' * 80}")
    # Telegram notification — ONLY on success (scan completed without fatal errors)
    if scan_failed:
        print("[!] Scan completed with errors — no Telegram notification (per user preference).")
        return all_flagged
    if all_flagged:
        lines = [f"⚠️ PHISHING DETECTED", f"Total flagged: {len(all_flagged)}", f"Accounts scanned: {len(ACCOUNTS)}", ""]
        for i, m in enumerate(sorted(all_flagged, key=lambda x: x['score'], reverse=True)[:5], 1):
            lines.append(f"#{i} [{m['score']}⚠]")
            lines.append(f"From: {m['from']}")
            lines.append(f"Subject: {m['subject'][:60]}")
            if m['indicators']:
                lines.append(f"Indicators: {', '.join(m['indicators'][:3])}")
            lines.append("")
        lines.append("Automatically moved to Spam.")
        tg_send("\n".join(lines))
    else:
        tg_send("Gmail scan clean - 0 phishing detected.")
    return all_flagged

if __name__ == '__main__':
    import email.header
    main()