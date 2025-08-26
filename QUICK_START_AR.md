# دليل البدء السريع - HackSayer

## 🚀 أسرع طريقة للبدء

### 1. التثبيت في دقيقة واحدة
```bash
# نسخ الملفات
cd C:\Users\%USERNAME%\Desktop
git clone https://github.com/your-repo/HackSayer.git
cd HackSayer

# تثبيت المتطلبات
pip install requests beautifulsoup4 colorama
```

### 2. أول اختبار لك
```bash
# اختبار موقع تعليمي
python HackSayer.py -u http://testphp.vulnweb.com --full-scan

# سترى نتائج مثل:
# ✅ تم العثور على 122 ثغرة
# 🔍 SQL Injection في: /listproducts.php?cat=1
# 🔓 لوحة تحكم متاحة في: /admin
```

## 📋 الأوامر الجاهزة للاستخدام

### أوامر شائعة جداً
```bash
# فحص سريع للموقع
python HackSayer.py -u http://target.com --quick-scan

# فحص عميق مع تقارير
python HackSayer.py -u http://target.com --full-scan --output results.json

# اختبار تجاوز تسجيل الدخول
python auth_bypass_demo.py -u http://target.com/login.php
```

### أوامر متخصصة
```bash
# فحص SQL فقط
python HackSayer.py -u http://target.com --sql-injection

# البحث عن ملفات حساسة
python auth_bypass_demo.py -u http://target.com --sensitive-data

# اختبار مع التحايل
python advanced_evasion_demo.py -u http://target.com
```

## 🎯 أمثلة واقعية

### مثال 1: موقع WordPress
```bash
# اكتشاف لوحة تحكم WordPress
python HackSayer.py -u http://wordpress-site.com --admin-panels

# النتيجة:
# ✅ /wp-admin/ موجودة
# ✅ /wp-login.php موجود
# ⚠️ wp-config.php.bak موجود
```

### مثال 2: تطبيق PHP
```bash
# فحص شامل
python HackSayer.py -u http://php-app.com --full-scan

# النتائج المتوقعة:
# 🔴 SQL Injection في login.php
# 🟡 Directory listing في /uploads/
# 🟢 Missing security headers
```

### مثال 3: اختبار API
```bash
# فحص نقاط نهاية API
python HackSayer.py -u http://api.target.com --api-scan

# النتائج:
# 🔓 /api/admin/users بدون مصادقة
# 🔍 /api/backup.json متاح
```

## 🔍 قراءة النتائج بسرعة

### ما تعنيه الرموز
- 🔴 **عالية الخطورة**: SQL Injection, Auth Bypass
- 🟡 **متوسطة**: XSS, File Disclosure
- 🟢 **منخفضة**: Missing Headers

### ملف النتائج JSON
```json
{
  "target": "http://test.com",
  "critical_vulnerabilities": [
    {
      "type": "sql_injection",
      "url": "http://test.com/login.php",
      "parameter": "username",
      "payload": "admin' OR 1=1--"
    }
  ]
}
```

## ⚡ نصائح سريعة

### للمبتدئين
1. **ابدأ دائماً بمواقع تعليمية**
2. **استخدم الخيار --dry-run أولاً**
3. **احفظ النتائج دائماً**

### للمحترفين
1. **استخدم wordlists مخصصة**
2. **اضبط عدد الthreads حسب سرعة الاتصال**
3. **استخدم proxy لمراقبة الطلبات**

## 🛠️ حلول سريعة للمشاكل

### المشكلة: "Module not found"
```bash
pip install requests beautifulsoup4 colorama argparse
```

### المشكلة: "Connection timeout"
```bash
python HackSayer.py -u http://target.com --timeout 30
```

### المشكلة: "SSL error"
```bash
python HackSayer.py -u https://target.com --ignore-ssl
```

## 📊 سيناريوهات جاهزة

### سيناريو 1: اختبار موقع جديد
```bash
# الخطوات:
1. python HackSayer.py -u http://newsite.com --full-scan
2. python auth_bypass_demo.py -u http://newsite.com
3. python advanced_evasion_demo.py -u http://newsite.com
```

### سيناريو 2: فحص محدد للمصادقة
```bash
# فقط تسجيل الدخول
python auth_bypass_demo.py -u http://site.com/login.php --brute-force
```

### سيناريو 3: اختبار سريع
```bash
# في أقل من دقيقة
python HackSayer.py -u http://site.com --quick-scan --threads 20
```

## 🎯 ملخص في 3 خطوات

1. **تثبيت**: `pip install requests beautifulsoup4`
2. **اختبار**: `python HackSayer.py -u http://site.com --full-scan`
3. **تحليل**: افتح ملف `results.json` للنتائج

---

**💡 تذكير**: استخدم هذه الأداة فقط على المواقع التي تمتلكها أو لديك إذن صريح باختبارها!