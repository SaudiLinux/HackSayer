# HackSayer - أداة اختبار الاختراق الشاملة

<p align="center">
  <img src="assets/hacksayer_logo.svg" alt="hacksayer Logo" width="200">
  <br>
  <strong>أداة اختبار الاختراق المتقدمة للأنظمة العربية</strong>
  <br>
  <a href="#installation">التثبيت</a> •
  <a href="#usage">الاستخدام</a> •
  <a href="#features">الميزات</a> •
  <a href="#examples">الأمثلة</a>
</p>

## 🌟 نظرة عامة

**HackSayer** هي أداة اختبار اختراق متقدمة مفتوحة المصدر، مصممة خصيصاً للبيئات العربية والإسلامية. تدمج بين تقنيات الاستطلاع، فحص الثغرات، الاستغلال، وما بعد الاستغلال مع ميزات متقدمة لتجاوز أنظمة الحماية وكشف البيانات الحساسة.

### المميزات الرئيسية
- ✅ **دعم كامل للغة العربية**
- 🔍 **استطلاع متقدم** - DNS، المنافذ، تقنيات الويب
- 🐛 **فحص الثغرات** - SQL Injection، XSS، RCE
- 🎯 **استغلال تلقائي**
- 🛡️ **تقنيات التحايل** - تجاوز IDS/IPS
- 🔐 **تجاوز المصادقة** - brute force، session hijacking
- 📊 **تقارير شاملة** - JSON، HTML، CSV

## 🚀 التثبيت السريع

### المتطلبات
- Python 3.7+
- pip (مدير حزم Python)
- git

### التثبيت على Windows
```cmd
# استخدام PowerShell
git clone https://github.com/SaudiLinux/HackSayer.git
cd HackSayer
pip install -r requirements.txt
python HackSayer.py --help
```

### التثبيت على Linux/macOS
```bash
# نسخ الملفات
git clone https://github.com/SaudiLinux/HackSayer.git
cd HackSayer

# تثبيت المتطلبات
pip install -r requirements.txt

# جعل الملف قابل للتنفيذ
chmod +x HackSayer.py
```

### البيئة الافتراضية (مستحسن)
```bash
# إنشاء بيئة افتراضية
python -m venv hacksayer_env

# تفعيل البيئة
source hacksayer_env/bin/activate  # Linux/Mac
# أو
hacksayer_env\Scripts\activate     # Windows

# تثبيت المتطلبات
pip install -r requirements.txt
```

## 📖 الاستخدام

### الأوامر الأساسية
```bash
# فحص شامل
python HackSayer.py -u http://example.com --full-scan

# استطلاع فقط
python HackSayer.py -u http://example.com --recon

# فحص ثغرات فقط
python HackSayer.py -u http://example.com --scan

# مع تجاوز المصادقة
python auth_bypass_demo.py -u http://example.com

# التحايل على أنظمة الحماية
python advanced_evasion_demo.py -u http://example.com
```

### خيارات سطر الأوامر
```
الخيارات الأساسية:
  -u, --url           عنوان URL المستهدف
  -c, --config        مسار ملف الإعدادات
  -o, --output        دليل الإخراج للنتائج

الوحدات:
  --recon             الاستطلاع فقط
  --scan              فحص الثغرات فقط
  --exploit           الاستغلال
  --post              ما بعد الاستغلال
  --evade             تقنيات التحايل
  --full-scan         جميع الوحدات
  --auth-bypass       تجاوز المصادقة
  --sensitive-data    كشف البيانات الحساسة
```

## 🎯 أمثلة عملية

### مثال 1: فحص WordPress شامل
```bash
# 1. فحص شامل
python HackSayer.py -u https://wordpress-site.com --full-scan

# 2. اختبار لوحة الإدارة
python auth_bypass_demo.py -u https://wordpress-site.com/wp-admin

# 3. التحايل على حماية تسجيل الدخول
python advanced_evasion_demo.py -u https://wordpress-site.com/wp-login.php
```

### مثال 2: تطبيق PHP تقليدي
```bash
# 1. فحص تطبيق PHP
python HackSayer.py -u http://php-app.com/index.php?id=1 --scan

# 2. اختبار تجاوز المصادقة
python auth_bypass_demo.py -u http://php-app.com/admin/login.php

# 3. كشف ملفات النسخ الاحتياطي
python auth_bypass_demo.py -u http://php-app.com --sensitive-data
```

### مثال 3: واجهة API REST
```bash
# 1. استطلاع API
python HackSayer.py -u https://api.example.com/v1 --recon

# 2. فحص نقاط النهاية
python HackSayer.py -u https://api.example.com/v1/users --scan

# 3. التحايل على حماية API
python advanced_evasion_demo.py -u https://api.example.com/v1/users
```

## 🛡️ الميزات الأمنية المتقدمة

### تجاوز المصادقة (Auth Bypass)
- **الهجوم بالقوة الغاشمة**: تجربة كلمات مرور شائعة
- **حقن SQL للمصادقة**: تجاوز شاشات تسجيل الدخول
- **اختطاف الجلسات**: استخدام رموز الجلسة المسروقة
- **الارتقاء بالامتيازات**: الوصول لحسابات المدير
- **حشو بيانات الاعتماد**: استخدام بيانات مفقودة من خروقات سابقة

### التحايل على أنظمة الكشف (IDS/IPS Evasion)
- **تشفير الطلبات**: Base64، URL encoding، Hex encoding
- **تمويه الطلبات**: تغيير الرؤوس والمعلمات
- **تجزئة الطلبات**: تقسيم الطلبات لعدم اكتشافها
- **تأخير التوقيت**: محاكاة سلوك المستخدم الطبيعي
- **تدوير وكلاء المستخدم**: تجنب التعرف على الأنماط

### كشف البيانات الحساسة
- **لوحات الإدارة**: البحث عن واجهات الإدارة المخفية
- **ملفات النسخ الاحتياطي**: كشف ملفات backup القديمة
- **قواعد البيانات المكشوفة**: البحث عن قواعد بيانات غير محمية
- **الدلائل الحساسة**: كشف المجلدات الحساسة

## 📊 فهم النتائج

### مستويات الخطورة
- **حرج (Critical)**: ثغرات يمكن استغلالها مباشرة
- **مرتفع (High)**: ثغرات خطيرة تحتاج لظروف خاصة
- **متوسط (Medium)**: مشاكل أمنية مهمة
- **منخفض (Low)**: مشاكل بسيطة أو تحسينات

### ملفات النتائج
- `results/scan_[timestamp].json`: نتائج الفحص الكاملة
- `ids_evasion_report.json`: تقرير تقنيات التحايل
- `auth_bypass_demo_results.json`: نتائج تجاوز المصادقة
- `advanced_evasion_demo.json`: تقرير التحايل المتقدم

## 🔧 حل المشكلات الشائعة

### مشاكل التثبيت
```bash
# مشكلة: "pip not found"
python -m ensurepip --upgrade

# مشكلة: "Module not found"
pip install -r requirements.txt

# مشكلة: "Permission denied"
# Windows: تشغيل كمسؤول
# Linux/Mac: sudo chmod +x HackSayer.py
```

### مشاكل التشغيل
```bash
# مشكلة: "Connection timeout"
python HackSayer.py -u http://example.com --timeout 30

# مشكلة: "SSL certificate verify failed"
python HackSayer.py -u https://example.com --no-verify-ssl

# مشكلة: أنظمة الحماية تحظر الطلبات
python advanced_evasion_demo.py -u http://example.com
```

## 💡 نصائح سريعة للمبتدئين

### قبل البدء
1. ✅ تأكد من صلاحياتك القانونية
2. 📝 احصل على إذن خطي من مالك النظام
3. 🧪 ابدأ بالبيئات التجريبية

### أثناء الاستخدام
1. 🐌 ابدأ بالفحص الخفيف
2. 📊 راقب معدل الطلبات
3. 💾 احفظ النتائج بانتظام

### بعد الانتهاء
1. 📋 راجع جميع النتائج
2. 📄 أنشئ تقريراً شاملاً
3. 🔧 قدم التوصيات للإصلاح

## 🎯 سيناريوهات جاهزة

### سيناريو 1: موقع WordPress كامل
```bash
# خطوة 1: استطلاع
python HackSayer.py -u https://wordpress.com --recon

# خطوة 2: فحص الثغرات
python HackSayer.py -u https://wordpress.com --scan

# خطوة 3: اختبار لوحة الإدارة
python auth_bypass_demo.py -u https://wordpress.com/wp-admin
```

### سيناريو 2: تطبيق تجاري
```bash
# خطوة 1: فحص شامل
python HackSayer.py -u https://business-app.com --full-scan

# خطوة 2: التحايل على الحماية
python advanced_evasion_demo.py -u https://business-app.com

# خطوة 3: كشف البيانات الحساسة
python auth_bypass_demo.py -u https://business-app.com --sensitive-data
```

## 🚀 بدء الاستخدام الفوري (دقيقة واحدة)

```bash
# 1. نسخ الملفات
git clone https://github.com/SaudiLinux/HackSayer.git

# 2. الدخول للمجلد
cd HackSayer

# 3. التثبيت
pip install -r requirements.txt

# 4. أول اختبار
python HackSayer.py -u http://testphp.vulnweb.com --recon
```

## ⚠️ إخلاء المسؤولية والاستخدام الأخلاقي

### المسؤولية القانونية
**هذه الأداة مخصصة للأغراض التعليمية واختبارات الاختراق المصرح بها فقط.**

### متطلبات الاستخدام
- ✅ الحصول على تصريح خطي من مالك النظام
- ✅ الالتزام بقوانين البلد
- ✅ اتباع مبادئ الإفصاح المسؤول
- ✅ استخدام في البيئات التجريبية أولاً

### ممنوع الاستخدام في
- ❌ الأنظمة بدون إذن صريح
- ❌ الاختبارات غير القانونية
- ❌ الأنشطة الخبيثة أو الإجرامية
- ❌ انتهاك خصوصية المستخدمين

## 📞 الدعم الفني والمجتمع

### طرق التواصل
- **📧 البريد الإلكتروني**: SayerLinux@gmail.com
- **🐙 GitHub Issues**: [إنشاء مشكلة](https://github.com/SaudiLinux/HackSayer/issues)
- **💬 Discord**: [انضم لمجتمعنا](https://discord.gg/saudilinux)

### المصادر
- **📖 الوثائق**: [مستندات HackSayer](https://github.com/SaudiLinux/HackSayer/wiki)
- **🎥 فيديوهات**: [قناة تعليمية](https://youtube.com/@SayerLinux)
- **📱 تليجرام**: [مجموعة الدعم](https://t.me/SayerLinux)

## 📄 الرخصة

هذا المشروع مرخص تحت **رخصة MIT** - راجع ملف [LICENSE](LICENSE) للتفاصيل.

## 🔄 سجل التحديثات

### الإصدار 1.0.0 (الإصدار الأول)
- ✅ الاستطلاع المتقدم
- ✅ فحص الثغرات التلقائي
- ✅ الإطار الاستغلالي
- ✅ تحليل ما بعد الاستغلال
- ✅ تقنيات التحايل على IDS/IPS
- ✅ تجاوز المصادقة
- ✅ كشف البيانات الحساسة
- ✅ تقارير متعددة التنسيقات
- ✅ دعم كامل للغة العربية

---

<div align="center">
  <strong>تم التطوير بحب ❤️ بواسطة SayerLinux</strong>
  <br>
  <em>لخدمة مجتمع الأمن السيبراني العربي</em>
</div>
