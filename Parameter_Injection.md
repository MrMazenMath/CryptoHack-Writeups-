```markdown
# حل تحدي Parameter Injection على CryptoHack: مغامرة السوكت والتشفير! 🚀

> **تحذير:** المقال ده بيحتوي على الحل الكامل لتحدي **Parameter Injection** من CryptoHack. لو عايز تحل التحدي بنفسك, جرب الأول وارجع لو احتجت تلميح!

## مقدمة
تحدي **Parameter Injection** من قسم **Crypto** على [CryptoHack](https://cryptohack.org/) كان زي رحلة مليانة تشويق! 😄 الهدف كان نستغل ثغرة في تبادل مفاتيح **Diffie-Hellman** عشان نفك تشفير علم (flag) مشفر بـ **AES-CBC**. التحدي ده مزيج رائع من برمجة السوكت, التعامل مع JSON, وفهم أساسيات التشفير. بعد معاناة مع أخطاء زي `JSONDecodeError` ومشاكل الحشو, وصلت للعلم:  
**`crypto{n1c3_0n3_m4ll0ry!!!!!!!!}`** 🎉  
في المقال ده, هشارك رحلتي خطوة بخطوة, من التحليل للحل, مع كل الأخطاء اللي واجهتني والدروس اللي اتعلمتها.

## فهم التحدي
### السيناريو
- أليس (Alice) وبوب (Bob) بيتبادلوا مفاتيح Diffie-Hellman عبر خادم على العنوان `socket.cryptohack.org:13371`.
- أليس بتبعت المعاملات:
  - \( p \): عدد أولي كبير.
  - \( g \): المولد (generator).
  - \( A \): القيمة العامة لأليس (\( A = g^a \mod p \)).
- بوب بيبعت:
  - \( B \): القيمة العامة لبوب (\( B = g^b \mod p \)).
- بعدين, أليس بتبعت نص مشفر (ciphertext) مع متجه تهيئة (IV) باستخدام **AES-CBC**.
- دورنا (كـ Mallory في هجوم man-in-the-middle) نعدّل البيانات عشان نعرف المفتاح المشترك \( K \) ونفك تشفير العلم.

### المطلوب
- نعدّل بيانات أليس وبوب عشان المفتاح المشترك \( K \) يبقى قيمة معروفة (زي \( K = 1 \)).
- نستخدم \( K \) لاشتقاق مفتاح AES وفك تشفير النص المشفر للحصول على العلم.

### الفكرة الأساسية
لو خلينا \( g = 1 \), هيحصل الآتي:
- \( A = g^a \mod p = 1^a \mod p = 1 \).
- \( B = g^b \mod p = 1^b \mod p = 1 \).
- المفتاح المشترك:
  - عند أليس: \( K = B^a \mod p = 1^a \mod p = 1 \).
  - عند بوب: \( K = A^b \mod p = 1^b \mod p = 1 \).
- بكده, \( K = 1 \), ونقدر نستخدمه لاشتقاق مفتاح AES وفك التشفير.

## التحليل والحل
### 1. الاتصال بالخادم
- استخدمنا مكتبة `socket` في Python للاتصال بـ `socket.cryptohack.org:13371`.
- ضبطنا مهلة زمنية (`settimeout(10)`) عشان نتجنب التعليق لو الخادم ما استجابش.
- كتبنا دالة `recv_line` لقراءة البيانات سطرًا بسطر بدل `recv(1024)` اللي ممكن تقطّع البيانات.

### 2. استقبال وتعديل بيانات أليس
- البيانات من أليس بتيجي كـ JSON مع نصوص زيادة, زي:
  ```
  Intercepted from Alice: {"p": "0x...", "g": "0x02", "A": "0x..."}
  ```
- نظفنا البيانات باستخدام:
  ```python
  data = data.replace("Intercepted from Alice:", "").strip()
  data = data.split("Send to Bob:")[0].strip()
  ```
- حللنا JSON بـ `json.loads` وعدّلنا \( g \) لـ `hex(1)` (يعني \( g = 1 \)).
- أرسلنا البيانات المعدلة لبوب.

### 3. استقبال وتعديل بيانات بوب
- بوب بيبعت بيانات زي:
  ```
  Send to Bob: Intercepted from Bob: {"B": "0x1"}
  ```
- نظفنا البيانات بـ:
  ```python
  bob_data = bob_data.replace("Send to Bob:", "").replace("Intercepted from Bob:", "").strip()
  bob_data = bob_data.split("Send to Alice:")[0].strip()
  ```
- حللنا JSON, وتأكدنا إن \( B = 1 \) (وهو متوقع لأن \( g = 1 \)).
- عدّلنا \( B = hex(1) \) وأرسلناها لأليس.

### 4. استقبال البيانات المشفرة
- أليس بتبعت النص المشفر كـ JSON:
  ```
  Send to Alice: Intercepted from Alice: {"iv": "...", "encrypted_flag": "..."}
  ```
- نظفنا البيانات بـ:
  ```python
  encrypted_data = encrypted_data.replace("Send to Alice:", "").replace("Intercepted from Alice:", "").strip()
  encrypted_data = encrypted_data.split("Encrypted data:")[0].strip()
  ```
- حللنا JSON واستخرجنا:
  - `iv`: متجه التهيئة (hex-encoded).
  - `encrypted_flag`: النص المشفر (hex-encoded).
- حولناهم لبايتات باستخدام `binascii.unhexlify`.

### 5. فك التشفير
- اشتقينا مفتاح AES من \( K = 1 \):
  ```python
  K = 1
  key = hashlib.sha1(str(K).encode()).digest()[:16]
  ```
- استخدمنا مكتبة `pycryptodome` لفك تشفير النص بـ AES-CBC:
  ```python
  cipher = AES.new(key, AES.MODE_CBC, iv)
  plaintext = cipher.decrypt(ciphertext)
  ```
- حاولنا نزيل الحشو (PKCS#7) بـ:
  ```python
  padding_len = plaintext[-1]
  plaintext = plaintext[:-padding_len]
  ```
- لكن واجهنا مشكلة إن الحشو كان غير صالح, فطبعنا النص الخام بدون إزالة الحشو:
  ```python
  plaintext.decode('utf-8', errors='ignore')
  ```
- النتيجة كانت العلم: **`crypto{n1c3_0n3_m4ll0ry!!!!!!!!}`**!

## التحديات والأخطاء
رحلة الحل كانت مليانة تحديات, وكل خطأ علّمني حاجة جديدة:
1. **Timeout Error:**
   - الكود كان بيتوقف عند `Waiting for data...`.
   - الحل: أضفنا `settimeout(10)` ودالة `recv_line` لقراءة البيانات بدقة.
2. **JSONDecodeError:**
   - البيانات كانت بتيجي مع نصوص زيادة زي `"Send to Bob:"` و`"Intercepted from Alice:"`.
   - الحل: استخدمنا `replace` و`split` متعددة لتنظيف البيانات قبل `json.loads`.
3. **Invalid Padding:**
   - إزالة الحشو (PKCS#7) كانت بتفشل لأن `plaintext[-1]` كان قيمة غير صالحة.
   - الحل: طبعنا النص الخام بدون إزالة الحشو, وطلع العلم!
4. **SyntaxError:**
   - واجهنا خطأ في كتلة `except Exception as` بدون متغير.
   - الحل: عدّلناها لـ `except Exception as e`.

## الكود النهائي
> **تحذير:** الكود ده الحل الكامل للتحدي. لو عايز تحل بنفسك, بلاش تقراه!

```python
import socket
import json
import hashlib
from Crypto.Cipher import AES
import binascii

# دالة لقراءة سطر واحد
def recv_line(client):
    data = b""
    while not data.endswith(b'\n'):
        chunk = client.recv(1)
        if not chunk:
            break
        data += chunk
    return data.decode()

# الاتصال بالخادم
print("[*] Connecting to socket.cryptohack.org:13371")
client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client.settimeout(10)
try:
    client.connect(('socket.cryptohack.org', 13371))
except socket.timeout:
    print("[!] Connection timeout. Check your internet and try again.")
    client.close()
    exit(1)

# استقبال وتعديل بيانات أليس
print("[*] Waiting for data from Alice...")
try:
    data = recv_line(client)
    print(f"[*] Raw Alice data: {data}")
    if data.startswith("Intercepted from Alice:"):
        data = data.replace("Intercepted from Alice:", "").strip()
    data = data.split("Send to Bob:")[0].strip()
    print(f"[*] Cleaned Alice data: {data}")
    alice_data = json.loads(data)
    alice_data['g'] = hex(1)
    client.send((json.dumps(alice_data) + '\n').encode())
    print("[*] Sent modified Alice data (g = 1) to Bob")
except socket.timeout:
    print("[!] Timeout while receiving Alice data.")
    client.close()
    exit(1)
except json.JSONDecodeError as e:
    print(f"[!] JSON decode error: {e}")
    print(f"[!] Raw data: {data}")
    client.close()
    exit(1)

# استقبال وتعديل بيانات بوب
print("[*] Waiting for data from Bob...")
try:
    bob_data = recv_line(client)
    print(f"[*] Raw Bob data: {bob_data}")
    bob_data = bob_data.replace("Send to Bob:", "").replace("Intercepted from Bob:", "").strip()
    bob_data = bob_data.split("Send to Alice:")[0].strip()
    print(f"[*] Cleaned Bob data: {bob_data}")
    bob_data = json.loads(bob_data)
    print(f"[*] Parsed Bob data: {bob_data}")
    bob_data['B'] = hex(1)
    client.send((json.dumps(bob_data) + '\n').encode())
    print("[*] Sent modified data (B = 1) to Alice")
except socket.timeout:
    print("[!] Timeout while receiving Bob data.")
    client.close()
    exit(1)
except json.JSONDecodeError as e:
    print(f"[!] JSON decode error: {e}")
    print(f"[!] Raw data: {bob_data}")
    client.close()
    exit(1)

# استقبال البيانات المشفرة
print("[*] Waiting for encrypted data...")
try:
    encrypted_data = recv_line(client)
    print(f"[*] Raw encrypted data: {encrypted_data}")
    encrypted_data = encrypted_data.replace("Send to Alice:", "").replace("Intercepted from Alice:", "").strip()
    encrypted_data = encrypted_data.split("Encrypted data:")[0].strip()
    print(f"[*] Cleaned encrypted data: {encrypted_data}")
    encrypted_data = json.loads(encrypted_data)
    print(f"[*] Parsed encrypted data: {encrypted_data}")
except socket.timeout:
    print("[!] Timeout while receiving encrypted data.")
    client.close()
    exit(1)
except json.JSONDecodeError as e:
    print(f"[!] JSON decode error: {e}")
    print(f"[!] Raw data: {encrypted_data}")
    client.close()
    exit(1)

# استخراج ciphertext و IV
try:
    iv = binascii.unhexlify(encrypted_data['iv'])
    ciphertext = binascii.unhexlify(encrypted_data['encrypted_flag'])
    print(f"[*] IV: {iv.hex()}")
    print(f"[*] Ciphertext: {ciphertext.hex()}")
except KeyError as e:
    print(f"[!] Key error: {e}")
    print(f"[!] Encrypted data: {encrypted_data}")
    client.close()
    exit(1)

# اشتقاق مفتاح AES باستخدام K = 1
K = 1
key = hashlib.sha1(str(K).encode()).digest()[:16]
print(f"[*] AES key: {key.hex()}")

# فك تشفير AES-CBC
try:
    cipher = AES.new(key, AES.MODE_CBC, iv)
    plaintext = cipher.decrypt(ciphertext)
    print(f"[*] Raw decrypted plaintext (hex): {plaintext.hex()}")
    # التحقق من الحشو (PKCS#7)
    padding_len = plaintext[-1]
    if 1 <= padding_len <= 16 and plaintext[-padding_len:] == bytes([padding_len]) * padding_len:
        plaintext = plaintext[:-padding_len]
        print(f"[*] Decrypted flag: {plaintext.decode()}")
    else:
        print(f"[!] Invalid padding: padding_len={padding_len}, plaintext={plaintext.hex()}")
        print(f"[*] Decrypted flag (without padding removal): {plaintext.decode('utf-8', errors='ignore')}")
except UnicodeDecodeError as e:
    print(f"[!] Unicode decode error: {e}")
    print(f"[*] Raw plaintext (hex): {plaintext.hex()}")
    print(f"[*] Decrypted flag (raw): {plaintext.decode('utf-8', errors='ignore')}")
except Exception as e:
    print(f"[!] Decryption error: {e}")
    client.close()
    exit(1)

# إغلاق الاتصال
client.close()
```

## النتيجة
بعد رحلة مليانة أخطاء وتصحيحات, وصلنا للعلم:
**`crypto{n1c3_0n3_m4ll0ry!!!!!!!!}`** 🎉  
العلم بيلمح لدور **Mallory** في هجوم man-in-the-middle, وكان شعور النصر لا يُضاهى! 😎

## نصائح للمبتدئين
- **برمجة السوكت:** استخدم دالة زي `recv_line` للتعامل مع بيانات السوكت بدقة.
- **تنظيف البيانات:** كن جاهز لنصوص زيادة في JSON. استخدم `replace` و`split` بمرونة.
- **التشفير:** افهم أساسيات **AES-CBC** والحشو (PKCS#7) قبل ما تبدأ.
- **تصحيح الأخطاء:** اطبع البيانات الخام دايمًا (raw data) عشان تعرف مصدر المشكلة.
- **الصبر مفتاح النجاح:** الأخطاء جزء من الرحلة. كل خطأ بيعلمك حاجة جديدة!

## دروس مستفادة
- **Diffie-Hellman:** فهمت إزاي تعديل \( g \) ممكن يخرّب تبادل المفاتيح.
- **برمجة السوكت:** اتعلمت التعامل مع بيانات السوكت وتنظيفها.
- **AES-CBC:** عرفت إزاي أفك تشفير النصوص باستخدام مفتاح وIV.
- **الحشو:** اكتشفت أهمية التحقق من الحشو (PKCS#7) والتعامل مع الحالات غير الصالحة.
- **المثابرة:** واجهت أخطاء زي Timeout وJSON decode, بس الصبر كان مفتاح النجاح!

## الخاتمة
تحدي **Parameter Injection** كان مغامرة حقيقية! 😄 تعلمت منه كتير عن التشفير, السوكت, وتصحيح الأخطاء. شكر خاص لـ [CryptoHack](https://cryptohack.org/) على التحديات الممتعة, وللمجتمع اللي دايمًا بيدعم. لو عايز تحل تحديات زي دي, ابدأ بـ Python, مكتبة `pycryptodome`, وشوية صبر! 🚀  
لو عجبك الـ write-up أو عندك أسئلة عن التحدي, اكتب تعليق أو تواصل معايا! مستني أشوفكم في التحدي الجاي! 😎
