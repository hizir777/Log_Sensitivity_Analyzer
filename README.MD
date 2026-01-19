
---

# 🔒 Log Sensitivity Analyzer - Forensic-grade DLP Engine

**Log Sensitivity Analyzer**, log dosyaları içerisindeki hassas verileri (PII) ve gizli anahtarları (Secrets) tespit etmek, doğrulamak ve maskelemek için geliştirilmiş, adli bilişim (forensic) standartlarında bir **Veri Sızıntısı Önleme (DLP)** aracıdır.

## 🚀 Öne Çıkan Özellikler

Proje, basit bir arama motorunun ötesinde hibrit bir tespit ve doğrulama mimarisi sunar:

* **Algoritmik Doğrulama (Mathematical Validators):** TCKN için **Modulo 11** ve Kredi Kartları için **Luhn (Mod 10)** algoritmalarını kullanarak hatalı bulgu (false positive) oranını minimize eder.


* **Entropi Analizi (Shannon Entropy):** Belirli bir kalıba uymayan karmaşık API anahtarlarını ve şifreleri **4.5 bits** üzerindeki rastgelelik oranına göre (Shannon Entropy) tespit eder.


* **ReDoS Güvenliği:** Tüm arama desenleri, siber saldırılara (Regular Expression Denial of Service) karşı optimize edilmiş ve atomik gruplandırmalarla güçlendirilmiştir.


* **Unix I/O & Stream Processing:** Bellek dostu (line-by-line generator) yapısı sayesinde büyük log dosyalarını sabit **~15MB RAM** kullanımıyla işleyebilir.


* **Gelişmiş Risk Skorlama:** Bulguları türlerine göre ağırlıklandırarak (Kritik, Yüksek, Orta, Düşük) 10.0 üzerinden bir risk puanı hesaplar.



---

## 🛠️ Kurulum (Sanal Ortam)

Projeyi izole ve güvenli bir şekilde çalıştırmak için aşağıdaki adımları izleyin:

```bash
# 1. Projeyi klonlayın
git clone https://github.com/kullaniciadi/Log_Sensitivity_Analyzer.git
cd Log_Sensitivity_Analyzer

# 2. Sanal ortamı (venv) kurun ve aktif edin
python3 -m venv venv
source venv/bin/activate  # Windows için: venv\Scripts\activate

# 3. Bağımlılıkları yükleyin
pip install -r requirements.txt

# 4. Otomasyon kurulumunu ve sistem kontrolünü tamamlayın
chmod +x setup.sh && ./setup.sh

```

---

## 💻 Kullanım Şekilleri

### 1. İnteraktif Dashboard (Streamlit UI)

En kapsamlı ve görsel deneyim için Streamlit arayüzünü kullanın:

```bash

streamlit run src/ui/app.py

```

* **Özellikler:** Sürükle-bırak dosya yükleme, canlı risk metrikleri, PII dağılım grafikleri, entropi grafiği ve "Run Full Audit" butonu.

### 2. Terminal (CLI) Modu

Hızlı taramalar ve DevOps entegrasyonu için idealdir:

```bash

# Tek dosya tarama
python src/core/engine.py --scan application.log

# Canlı log izleme (Pipe)
tail -f access.log | python src/core/engine.py --scan -

# JSON formatında SIEM raporu üretme
python src/core/engine.py --scan app.log --json > report.json

```

---

## 🏗️ Proje Mimarisi

Sistem, profesyonel standartlara uygun modüler bir hiyerarşiye sahiptir:

```text
Log_Sensitivity_Analyzer/
├── src/
│   ├── core/           # Arama desenleri (patterns.py) ve Ana Motor (engine.py)
│   ├── validators/     # Algoritmik doğrulama motorları (tckn_validator.py, luhn_validator.py)
│   └── ui/             # Streamlit Dashboard kodları (app.py)
├── tests/              # 41 adet otomatik test senaryosu ve Canary Logs
├── researchs/          # AI destekli teknik araştırma dökümanları
└── specs/              # Proje metadata ve konfigürasyon (project_info.json)

```

---

## 🛡️ Otomasyon ve Güvenilirlik

Proje, kendi kendini denetleme ve raporlama yeteneğine sahiptir:

* **Auto-Control:** Açılışta Python sürümünü, bağımlılıkları ve dosya bütünlüğünü kontrol eder.


* **Auto-Test:** `./run_tests.sh` komutuyla tüm sistemi saniyeler içinde 41 testten geçirir ve %100 doğruluk başarısını kanıtlar.


* **CI/CD Ready:** GitLab ve GitHub Actions gibi otomasyon hatlarına doğrudan entegre edilebilir exit kodlarına (0/1) sahiptir.



---

## 📜 KVKK ve GDPR Uyumluluğu

| İlke | Teknik Karşılık |
| --- | --- |
| **Bütünlük (KVKK Madde 12)** | Cryptographic/Matematiksel doğrulayıcılar ile verinin kesin tespiti.|
| **Güvenlik (GDPR Madde 32)** | Verilerin asla plaintext gösterilmemesi ve forensic masking.|
| **Hesap Verilebilirlik (GDPR Madde 5)** | Zaman damgalı JSON raporları ve denetlenebilir audit trail.|

---