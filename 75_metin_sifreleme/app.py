"""Metin Şifreleme Aracı — Flask. Caesar, Vigenère, AES (Fernet, parola tabanlı).
"""
import base64
from flask import Flask, request, render_template_string
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

app = Flask(__name__)
SALT = b"static-demo-salt-16b"


def caesar(text, key, dec=False):
    k = (-int(key) if dec else int(key)) % 26
    out = []
    for ch in text:
        if ch.isupper():
            out.append(chr((ord(ch) - 65 + k) % 26 + 65))
        elif ch.islower():
            out.append(chr((ord(ch) - 97 + k) % 26 + 97))
        else:
            out.append(ch)
    return "".join(out)


def vigenere(text, key, dec=False):
    key = [ord(c.lower()) - 97 for c in key if c.isalpha()]
    if not key:
        return text
    out = []; ki = 0
    for ch in text:
        if ch.isalpha():
            base = 65 if ch.isupper() else 97
            shift = -key[ki % len(key)] if dec else key[ki % len(key)]
            out.append(chr((ord(ch) - base + shift) % 26 + base)); ki += 1
        else:
            out.append(ch)
    return "".join(out)


def aes_key(password):
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=SALT, iterations=200_000)
    return Fernet(base64.urlsafe_b64encode(kdf.derive(password.encode())))


PAGE = """<!doctype html><html lang=tr><head><meta charset=utf-8>
<meta name=viewport content="width=device-width,initial-scale=1"><title>Metin Şifreleme</title><style>
body{font-family:system-ui,sans-serif;max-width:640px;margin:0 auto;padding:1rem;background:#0f172a;color:#e2e8f0}
h1{color:#a78bfa}textarea,input,select{width:100%;padding:.6rem;margin:.3rem 0;border:1px solid #334155;
border-radius:8px;background:#1e293b;color:#fff;font:inherit;box-sizing:border-box}
button{background:#7c3aed;color:#fff;border:0;padding:.6rem 1.2rem;border-radius:8px;cursor:pointer;margin:.2rem .2rem 0 0}
.out{background:#1e293b;border-radius:8px;padding:1rem;word-break:break-all;white-space:pre-wrap;min-height:2em}
.err{color:#f87171}label{font-size:.85rem;color:#94a3b8}</style></head><body>
<h1>🔏 Metin Şifreleme</h1>
<form method=post>
<label>Yöntem</label>
<select name=method>{% for m in ['caesar','vigenere','aes'] %}
<option value={{m}} {{'selected' if m==method}}>{{m|upper}}</option>{% endfor %}</select>
<label>Anahtar (Caesar: sayı · Vigenère: kelime · AES: parola)</label>
<input name=key value="{{key}}" required>
<label>Metin</label><textarea name=text rows=5 required>{{text}}</textarea>
<button name=op value=enc>🔒 Şifrele</button>
<button name=op value=dec>🔓 Çöz</button>
</form>
{% if result is not none %}<h3>Sonuç</h3><div class="out {{'err' if error}}">{{result}}</div>{% endif %}
</body></html>"""


@app.route("/", methods=["GET", "POST"])
def index():
    method = request.form.get("method", "caesar")
    key = request.form.get("key", "")
    text = request.form.get("text", "")
    result = None; error = False
    if request.method == "POST":
        dec = request.form.get("op") == "dec"
        try:
            if method == "caesar":
                result = caesar(text, key, dec)
            elif method == "vigenere":
                result = vigenere(text, key, dec)
            else:
                f = aes_key(key)
                result = (f.decrypt(text.encode()).decode() if dec
                          else f.encrypt(text.encode()).decode())
        except (InvalidToken, ValueError):
            result = "❌ Çözme hatası — anahtar yanlış veya bozuk şifreli metin."; error = True
        except Exception as e:
            result = f"❌ Hata: {e}"; error = True
    return render_template_string(PAGE, method=method, key=key, text=text,
                                  result=result, error=error)


if __name__ == "__main__":
    app.run(debug=True, port=5000)
