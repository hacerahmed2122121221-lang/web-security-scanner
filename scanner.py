import requests
from bs4 import BeautifulSoup

def scan_target(target_url):
    """
    دالة شاملة لفحص الموقع المستهدف وإرجاع قائمة بالثغرات والملاحظات المكتشفة
    """
    findings = []
    
    # التأكد من أن الرابط يبدأ بـ http أو https
    if not target_url.startswith("http://") and not target_url.startswith("https://"):
        target_url = "https://" + target_url

    # إعداد الـ Headers لمحاكاة متصفح حقيقي وتجنب الحظر
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AhmedSecurityScanner/1.0"
    }

    try:
        # إرسال طلب HTTP للموقع المستهدف
        response = requests.get(target_url, headers=headers, timeout=10, allow_redirects=True)
        resp_headers = response.headers

        # ----------------------------------------------------
        # 1. فحص رؤوس الأمان (Security Headers Check)
        # ----------------------------------------------------
        
        # فحص رأس Strict-Transport-Security (HSTS)
        if "Strict-Transport-Security" not in resp_headers:
            findings.append({
                "severity": "Medium",
                "title": "رأس حماية مفقود: HSTS",
                "description": "رأس Strict-Transport-Security غير موجود. هذا قد يجع عرضة لهجمات Man-in-the-Middle."
            })
        else:
            findings.append({
                "severity": "Info",
                "title": "تم العثور على رأس HSTS",
                "description": "الموقع يدعم الاتصال الآمن والمشفر بشكل صحيح."
            })

        # فحص رأس Content-Security-Policy (CSP)
        if "Content-Security-Policy" not in resp_headers:
            findings.append({
                "severity": "Medium",
                "title": "رأس حماية مفقود: CSP",
                "description": "رأس سياسة الأمان للمحتوى (CSP) غير موجود، مما يزيد من احتمالية ثغرات XSS."
            })
        else:
            findings.append({
                "severity": "Info",
                "title": "تم العثور على رأس CSP",
                "description": "الموقع يمتلك سياسة أمان للمحتوى تحميه من تشغيل نصوص خبيثة."
            })

        # فحص رأس X-Frame-Options
        if "X-Frame-Options" not in resp_headers:
            findings.append({
                "severity": "Low",
                "title": "رأس حماية مفقود: X-Frame-Options",
                "description": "الموقع قد يكون عرضة لهجمات التضمين الخبيث (Clickjacking)."
            })

        # ----------------------------------------------------
        # 2. فحص الملفات الحساسة (Sensitive Files Discovery)
        # ----------------------------------------------------
        sensitive_paths = ["/robots.txt", "/.env", "/sitemap.xml", "/.git/HEAD"]
        
        for path in sensitive_paths:
            file_url = target_url.rstrip("/") + path
            try:
                file_res = requests.get(file_url, headers=headers, timeout=5)
                if file_res.status_code == 200:
                    # التحقق من أن الصفحة ليست صفحة خطأ مخصصة تعيد 200 كذبياً
                    if "text/html" in file_res.headers.get("Content-Type", "") and len(file_res.text) < 100:
                        continue
                        
                    severity = "High" if path in ["/.env", "/.git/HEAD"] else "Low"
                    findings.append({
                        "severity": severity,
                        "title": f"ملف حساس متاح للعامة: {path}",
                        "description": "تم العثور على ملف حساس مكشوف قد يحتوي على معلومات سرية أو مسارات للنظام."
                    })
            except requests.RequestException:
                pass

    except requests.RequestException as e:
        findings.append({
            "severity": "High",
            "title": "فشل الاتصال بالموقع",
            "description": f"تعذر الوصول إلى الرابط المستهدف. التأكد من صحة الرابط. الخطأ: {str(e)}"
        })

    return findings
