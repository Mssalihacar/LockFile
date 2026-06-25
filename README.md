# LockFile
# LockFile - Güvenli Dosya Şifreleme ve Depolama Sistemi

Bu proje, hassas dosyaları gelişmiş kriptografik yöntemlerle şifrelemek, saklamak ve yetkisiz erişimleri engellemek amacıyla geliştirilmiş güvenli bir dosya kasası uygulamasıdır. Proje, hem backend şifreleme motorunu hem de kullanıcı dostu bir web arayüzünü içerir.

## 🚀 Özellikler
* **Gelişmiş Kriptografi:** Dosyaların güvenliği için AES-GCM tabanlı simetrik şifreleme ve bütünlük kontrolü.
* **Güvenli Anahtar Türetme:** Kullanıcı şifrelerinden anahtar üretimi için PBKDF2 / KDF mekanizmaları ve benzersiz Salt kullanımı.
* **Veritabanı Yönetimi:** Kullanıcı bilgileri ve dosya meta-verilerinin SQLite üzerinde güvenli bir şekilde saklanması.
* **Web Arayüzü:** Flask tabanlı, kullanıcı kayıt, giriş ve dosya yükleme/indirme işlemlerini yöneten dinamik paneller.
* **Erişim Kontrolü (ACL):** Dosya sahipliği doğrulaması ve yetkisiz dosya indirme girişimlerinin engellenmesi.

## 🛠️ Kullanılan Teknolojiler
* **Dil:** Python
* **Web Framework:** Flask
* **Kriptografi:** `cryptography` kütüphanesi
* **Veritabanı:** SQLite3

## 📦 Kurulum ve Çalıştırma

Projeyi yerel bilgisayarınızda veya bir Raspberry Pi üzerinde çalıştırmak için aşağıdaki adımları takip edebilirsiniz.

### 1. Depoyu Klonlayın
```bash
git clone [https://github.com/Mssalihacar/LockFile.git](https://github.com/Mssalihacar/LockFile.git)
cd LockFile
