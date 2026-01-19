
---

# 🤝 Contributing to Log Sensitivity Analyzer

Öncelikle bu projeye katkı sağlamak istediğiniz için teşekkürler! **Log Sensitivity Analyzer**, KVKK ve GDPR uyumluluğunu hedefleyen profesyonel bir güvenlik aracıdır. Bu nedenle, yapılacak tüm katkıların yüksek kalite ve güvenlik standartlarına uygun olması beklenmektedir.

---

## 🏗️ Geliştirme Ortamı Kurulumu

Projeye katkı sağlamaya başlamadan önce yerel ortamınızı hazırlayın:

1. Projeyi forklayın ve yerel kopyanızı oluşturun.
2. Sanal bir Python ortamı (venv) kurun ve aktif edin.
3. Gereksinimleri yükleyin: `pip install -r requirements.txt`.
4. Ortamın doğruluğunu onaylamak için `./setup.sh` script'ini çalıştırın.



---

## 📏 Kodlama Standartları

Projenin kurumsal ve okunabilir kalması için şu kurallara sıkı sıkıya bağlıyız:

* 
**PEP 8 Uyumluluğu:** Tüm Python kodları PEP 8 standartlarına uygun olmalıdır.


* 
**Dokümantasyon:** Tüm fonksiyon ve sınıflar Google/Sphinx tarzı docstring içermelidir.


* 
**Modüler Yapı:** Yeni eklenen doğrulayıcılar `src/validators/` altına, desenler ise `src/core/patterns.py` dosyasına eklenmelidir.


* 
**Hata Yönetimi:** Tüm modüller, Unix I/O standartlarına uygun olarak başarı durumunda `0`, hata durumunda `1` exit kodu döndürmelidir.



---

## 🧪 Test Zorunluluğu

Bu proje, yüksek doğruluk oranını korumak için kapsamlı bir test süreci kullanır:

1. Eklenen her yeni özellik için `tests/` klasörü altında yeni bir unit test oluşturulmalıdır.


2. Mevcut 41 testin tamamı başarıyla geçmelidir.


3. Testleri koşturmak için `./run_tests.sh` script'ini kullanın.


4. 
**Canary Logs:** Yeni tespit desenleri ekleniyorsa, `canary_logs.json` dosyasına hem geçerli hem de geçersiz (false-positive) test vakaları eklenmelidir.



---

## 🔒 Güvenlik Politikası

Eğer projede bir güvenlik açığı bulursanız, lütfen bunu **Issues** üzerinden değil, doğrudan projenin ana geliştiricisine e-posta yoluyla bildirin. Siber güvenlik araçları geliştirdiğimiz için "Sorumlu Açıklama" (Responsible Disclosure) ilkesine önem veriyoruz.

* 
**Regex Güvenliği:** Yeni eklenen desenler ReDoS (Regular Expression Denial of Service) saldırılarına karşı optimize edilmelidir.


* 
**Veri Gizliliği:** Geliştirme sırasında gerçek PII (Kişisel Veri) kullanılmamalı, sadece sentetik/sahte veriler kullanılmalıdır.



---

## 🚀 Pull Request (PR) Süreci

1. Anlamlı bir branch ismi kullanın (örn: `feat/new-iban-validator` veya `fix/tckn-checksum`).
2. PR açıklamasında yaptığınız değişikliğin KVKK/GDPR "Bütünlük" veya "Hesap Verilebilirlik" ilkelerine nasıl katkı sağladığını belirtin.


3. Kod incelemesi (Code Review) sürecinde istenen değişiklikleri uygulayın.
4. Onay alındıktan sonra branch'iniz `main` ile birleştirilecektir.

---

**Log Sensitivity Analyzer**'ı birlikte daha güvenli hale getirdiğimiz için teşekkürler!

---
