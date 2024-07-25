import streamlit as st
import numpy as np
import pandas as pd
import warnings
import pickle
import ipaddress
import re
import urllib.request
import socket
import requests
import whois
import time
from datetime import date, datetime
from googlesearch import search
from bs4 import BeautifulSoup
from sklearn import metrics 

from dateutil.parser import parse as date_parse
from urllib.parse import urlparse
from streamlit_option_menu import option_menu

def import_feature_extraction():
    from feature import FeatureExtraction
    return FeatureExtraction

class FeatureExtraction:
    features = []
    def __init__(self,url):
        self.features = []
        self.url = url
        self.domain = ""
        self.whois_response = ""
        self.urlparse = ""
        self.response = ""
        self.soup = ""

        try:
            self.response = requests.get(url)
            self.soup = BeautifulSoup(self.response.text, 'html.parser')
        except:
            pass

        try:
            self.urlparse = urlparse(url)
            self.domain = self.urlparse.netloc
        except:
            pass

        try:
            self.whois_response = whois.whois(self.domain)
        except:
            pass


        self.features.append(self.UsingIp())
        self.features.append(self.longUrl())
        self.features.append(self.shortUrl())
        self.features.append(self.symbol())
        self.features.append(self.redirecting())
        self.features.append(self.prefixSuffix())
        self.features.append(self.SubDomains())
        self.features.append(self.Hppts())
        self.features.append(self.DomainRegLen())
        self.features.append(self.Favicon())
        

        self.features.append(self.NonStdPort())
        self.features.append(self.HTTPSDomainURL())
        self.features.append(self.RequestURL())
        self.features.append(self.AnchorURL())
        self.features.append(self.LinksInScriptTags())
        self.features.append(self.ServerFormHandler())
        self.features.append(self.InfoEmail())
        self.features.append(self.AbnormalURL())
        self.features.append(self.WebsiteForwarding())
        self.features.append(self.StatusBarCust())

        self.features.append(self.DisableRightClick())
        self.features.append(self.UsingPopupWindow())
        self.features.append(self.IframeRedirection())
        self.features.append(self.AgeofDomain())
        self.features.append(self.DNSRecording())
        self.features.append(self.WebsiteTraffic())
        self.features.append(self.PageRank())
        self.features.append(self.GoogleIndex())
        self.features.append(self.LinksPointingToPage())
        self.features.append(self.StatsReport())


    # 1.UsingIp
    def UsingIp(self):
        try:
            ipaddress.ip_address(self.url)
            return -1
        except:
            return 1

    # 2.longUrl
    def longUrl(self):
        if len(self.url) < 54:
            return 1
        if len(self.url) >= 54 and len(self.url) <= 75:
            return 0
        return -1

    # 3.shortUrl
    def shortUrl(self):
        match = re.search('bit\.ly|goo\.gl|shorte\.st|go2l\.ink|x\.co|ow\.ly|t\.co|tinyurl|tr\.im|is\.gd|cli\.gs|'
                    'yfrog\.com|migre\.me|ff\.im|tiny\.cc|url4\.eu|twit\.ac|su\.pr|twurl\.nl|snipurl\.com|'
                    'short\.to|BudURL\.com|ping\.fm|post\.ly|Just\.as|bkite\.com|snipr\.com|fic\.kr|loopt\.us|'
                    'doiop\.com|short\.ie|kl\.am|wp\.me|rubyurl\.com|om\.ly|to\.ly|bit\.do|t\.co|lnkd\.in|'
                    'db\.tt|qr\.ae|adf\.ly|goo\.gl|bitly\.com|cur\.lv|tinyurl\.com|ow\.ly|bit\.ly|ity\.im|'
                    'q\.gs|is\.gd|po\.st|bc\.vc|twitthis\.com|u\.to|j\.mp|buzurl\.com|cutt\.us|u\.bb|yourls\.org|'
                    'x\.co|prettylinkpro\.com|scrnch\.me|filoops\.info|vzturl\.com|qr\.net|1url\.com|tweez\.me|v\.gd|tr\.im|link\.zip\.net', self.url)
        if match:
            return -1
        return 1

    # 4.Symbol@
    def symbol(self):
        if re.findall("@",self.url):
            return -1
        return 1
    
    # 5.Redirecting//
    def redirecting(self):
        if self.url.rfind('//')>6:
            return -1
        return 1
    
    # 6.prefixSuffix
    def prefixSuffix(self):
        try:
            match = re.findall('\-', self.domain)
            if match:
                return -1
            return 1
        except:
            return -1
    
    # 7.SubDomains
    def SubDomains(self):
        dot_count = len(re.findall("\.", self.url))
        if dot_count == 1:
            return 1
        elif dot_count == 2:
            return 0
        return -1

    # 8.HTTPS
    def Hppts(self):
        try:
            https = self.urlparse.scheme
            if 'https' in https:
                return 1
            return -1
        except:
            return 1

    # 9.DomainRegLen
    def DomainRegLen(self):
        try:
            expiration_date = self.whois_response.expiration_date
            creation_date = self.whois_response.creation_date
            try:
                if(len(expiration_date)):
                    expiration_date = expiration_date[0]
            except:
                pass
            try:
                if(len(creation_date)):
                    creation_date = creation_date[0]
            except:
                pass

            age = (expiration_date.year-creation_date.year)*12+ (expiration_date.month-creation_date.month)
            if age >=12:
                return 1
            return -1
        except:
            return -1

    # 10. Favicon
    def Favicon(self):
        try:
            for head in self.soup.find_all('head'):
                for head.link in self.soup.find_all('link', href=True):
                    dots = [x.start(0) for x in re.finditer('\.', head.link['href'])]
                    if self.url in head.link['href'] or len(dots) == 1 or self.domain in head.link['href']:
                        return 1
            return -1
        except:
            return -1

    # 11. NonStdPort
    def NonStdPort(self):
        try:
            port = self.domain.split(":")
            if len(port)>1:
                return -1
            return 1
        except:
            return -1

    # 12. HTTPSDomainURL
    def HTTPSDomainURL(self):
        try:
            if 'https' in self.domain:
                return -1
            return 1
        except:
            return -1
    
    # 13. RequestURL
    def RequestURL(self):
        try:
            for img in self.soup.find_all('img', src=True):
                dots = [x.start(0) for x in re.finditer('\.', img['src'])]
                if self.url in img['src'] or self.domain in img['src'] or len(dots) == 1:
                    success = success + 1
                i = i+1

            for audio in self.soup.find_all('audio', src=True):
                dots = [x.start(0) for x in re.finditer('\.', audio['src'])]
                if self.url in audio['src'] or self.domain in audio['src'] or len(dots) == 1:
                    success = success + 1
                i = i+1

            for embed in self.soup.find_all('embed', src=True):
                dots = [x.start(0) for x in re.finditer('\.', embed['src'])]
                if self.url in embed['src'] or self.domain in embed['src'] or len(dots) == 1:
                    success = success + 1
                i = i+1

            for iframe in self.soup.find_all('iframe', src=True):
                dots = [x.start(0) for x in re.finditer('\.', iframe['src'])]
                if self.url in iframe['src'] or self.domain in iframe['src'] or len(dots) == 1:
                    success = success + 1
                i = i+1

            try:
                percentage = success/float(i) * 100
                if percentage < 22.0:
                    return 1
                elif((percentage >= 22.0) and (percentage < 61.0)):
                    return 0
                else:
                    return -1
            except:
                return 0
        except:
            return -1
    
    # 14. AnchorURL
    def AnchorURL(self):
        try:
            i,unsafe = 0,0
            for a in self.soup.find_all('a', href=True):
                if "#" in a['href'] or "javascript" in a['href'].lower() or "mailto" in a['href'].lower() or not (self.url in a['href'] or self.domain in a['href']):
                    unsafe = unsafe + 1
                i = i + 1

            try:
                percentage = unsafe / float(i) * 100
                if percentage < 31.0:
                    return 1
                elif ((percentage >= 31.0) and (percentage < 67.0)):
                    return 0
                else:
                    return -1
            except:
                return -1

        except:
            return -1

    # 15. LinksInScriptTags
    def LinksInScriptTags(self):
        try:
            i,success = 0,0
        
            for link in self.soup.find_all('link', href=True):
                dots = [x.start(0) for x in re.finditer('\.', link['href'])]
                if self.url in link['href'] or self.domain in link['href'] or len(dots) == 1:
                    success = success + 1
                i = i+1

            for script in self.soup.find_all('script', src=True):
                dots = [x.start(0) for x in re.finditer('\.', script['src'])]
                if self.url in script['src'] or self.domain in script['src'] or len(dots) == 1:
                    success = success + 1
                i = i+1

            try:
                percentage = success / float(i) * 100
                if percentage < 17.0:
                    return 1
                elif((percentage >= 17.0) and (percentage < 81.0)):
                    return 0
                else:
                    return -1
            except:
                return 0
        except:
            return -1

    # 16. ServerFormHandler
    def ServerFormHandler(self):
        try:
            if len(self.soup.find_all('form', action=True))==0:
                return 1
            else :
                for form in self.soup.find_all('form', action=True):
                    if form['action'] == "" or form['action'] == "about:blank":
                        return -1
                    elif self.url not in form['action'] and self.domain not in form['action']:
                        return 0
                    else:
                        return 1
        except:
            return -1

    # 17. InfoEmail
    def InfoEmail(self):
        try:
            if re.findall(r"[mail\(\)|mailto:?]", self.soap):
                return -1
            else:
                return 1
        except:
            return -1

    # 18. AbnormalURL
    def AbnormalURL(self):
        try:
            if self.response.text == self.whois_response:
                return 1
            else:
                return -1
        except:
            return -1

    # 19. WebsiteForwarding
    def WebsiteForwarding(self):
        try:
            if len(self.response.history) <= 1:
                return 1
            elif len(self.response.history) <= 4:
                return 0
            else:
                return -1
        except:
            return -1

    # 20. StatusBarCust
    def StatusBarCust(self):
        try:
            if re.findall("<script>.+onmouseover.+</script>", self.response.text):
                return 1
            else:
                return -1
        except:
            return -1

    # 21. DisableRightClick
    def DisableRightClick(self):
        try:
            if re.findall(r"event.button ?== ?2", self.response.text):
                return 1
            else:
                return -1
        except:
            return -1

    # 22. UsingPopupWindow
    def UsingPopupWindow(self):
        try:
            if re.findall(r"alert\(", self.response.text):
                return 1
            else:
                return -1
        except:
            return -1

    # 23. IframeRedirection
    def IframeRedirection(self):
        try:
            if re.findall(r"[<iframe>|<frameBorder>]", self.response.text):
                return 1
            else:
                return -1
        except:
            return -1

    # 24. AgeofDomain
    def AgeofDomain(self):
        try:
            creation_date = self.whois_response.creation_date
            try:
                if(len(creation_date)):
                    creation_date = creation_date[0]
            except:
                pass

            today  = date.today()
            age = (today.year-creation_date.year)*12+(today.month-creation_date.month)
            if age >=6:
                return 1
            return -1
        except:
            return -1

    # 25. DNSRecording    
    def DNSRecording(self):
        try:
            creation_date = self.whois_response.creation_date
            try:
                if(len(creation_date)):
                    creation_date = creation_date[0]
            except:
                pass

            today  = date.today()
            age = (today.year-creation_date.year)*12+(today.month-creation_date.month)
            if age >=6:
                return 1
            return -1
        except:
            return -1

    # 26. WebsiteTraffic   
    def WebsiteTraffic(self):
        try:
            rank = BeautifulSoup(urllib.request.urlopen("http://data.alexa.com/data?cli=10&dat=s&url=" + self.url).read(), "xml").find("REACH")['RANK']
            if (int(rank) < 100000):
                return 1
            return 0
        except :
            return -1

    # 27. PageRank
    def PageRank(self):
        try:
            prank_checker_response = requests.post("https://www.checkpagerank.net/index.php", {"name": self.domain})

            global_rank = int(re.findall(r"Global Rank: ([0-9]+)", self.rank_checker_response.text)[0])
            if global_rank > 0 and global_rank < 100000:
                return 1
            return -1
        except:
            return -1
            

    # 28. GoogleIndex
    def GoogleIndex(self):
        try:
            site = search(self.url, 5)
            if site:
                return 1
            else:
                return -1
        except:
            return 1

    # 29. LinksPointingToPage
    def LinksPointingToPage(self):
        try:
            number_of_links = len(re.findall(r"<a href=", self.response.text))
            if number_of_links == 0:
                return 1
            elif number_of_links <= 2:
                return 0
            else:
                return -1
        except:
            return -1

    # 30. StatsReport
    def StatsReport(self):
        try:
            url_match = re.search(
        'at\.ua|usa\.cc|baltazarpresentes\.com\.br|pe\.hu|esy\.es|hol\.es|sweddy\.com|myjino\.ru|96\.lt|ow\.ly', self.url)
            ip_address = socket.gethostbyname(self.domain)
            ip_match = re.search('146\.112\.61\.108|213\.174\.157\.151|121\.50\.168\.88|192\.185\.217\.116|78\.46\.211\.158|181\.174\.165\.13|46\.242\.145\.103|121\.50\.168\.40|83\.125\.22\.219|46\.242\.145\.98|'
                                '107\.151\.148\.44|107\.151\.148\.107|64\.70\.19\.203|199\.184\.144\.27|107\.151\.148\.108|107\.151\.148\.109|119\.28\.52\.61|54\.83\.43\.69|52\.69\.166\.231|216\.58\.192\.225|'
                                '118\.184\.25\.86|67\.208\.74\.71|23\.253\.126\.58|104\.239\.157\.210|175\.126\.123\.219|141\.8\.224\.221|10\.10\.10\.10|43\.229\.108\.32|103\.232\.215\.140|69\.172\.201\.153|'
                                '216\.218\.185\.162|54\.225\.104\.146|103\.243\.24\.98|199\.59\.243\.120|31\.170\.160\.61|213\.19\.128\.77|62\.113\.226\.131|208\.100\.26\.234|195\.16\.127\.102|195\.16\.127\.157|'
                                '34\.196\.13\.28|103\.224\.212\.222|172\.217\.4\.225|54\.72\.9\.51|192\.64\.147\.141|198\.200\.56\.183|23\.253\.164\.103|52\.48\.191\.26|52\.214\.197\.72|87\.98\.255\.18|209\.99\.17\.27|'
                                '216\.38\.62\.18|104\.130\.124\.96|47\.89\.58\.141|78\.46\.211\.158|54\.86\.225\.156|54\.82\.156\.19|37\.157\.192\.102|204\.11\.56\.48|110\.34\.231\.42', ip_address)
            if url_match:
                return -1
            elif ip_match:
                return -1
            return 1
        except:
            return 1
    
    def getFeaturesList(self):
        return self.features



# Load the model
with open("Phishing-URL-Detection/gradient_boosting_model.pkl", "rb") as file:
    gbc = pickle.load(file)

# Configure Streamlit page settings
st.set_page_config(
    page_title="Phishing Detection",
    page_icon="shield",
    layout="centered",
    initial_sidebar_state="collapsed"
)

    # Set the background colors
st.markdown(
    """
    <style>
    body {
        background-image: "C:/User/user/fix bismillah web - Copy/Desain tanpa judul (1).png";
        background-size: cover;
        background-repeat: no-repeat;
        background-attachment: fixed;
    }
    .text-container {
        background-color: rgba(0, 0, 0, 0.5);  /* Semi-transparent background */
        color: white;  /* White text color */
        padding: 20px;
        border-radius: 10px;
    }
    .st-bw {
        background-color: #eeeeee; /* White background for widgets */
    }
    .st-cq {
        background-color: #cccccc; /* Gray background for chat input */
        border-radius: 10px; /* Add rounded corners */
        padding: 8px 12px; /* Add padding for input text */
        color: black; /* Set text color */
    }
    .st-cx {
        background-color: white; /* White background for chat messages */
    }
    .sidebar .block-container {
        background-color: #f0f0f0; /* Light gray background for sidebar */
        border-radius: 10px; /* Add rounded corners */
        padding: 10px; /* Add some padding for spacing */
    }
    .top-right-image-container {
        position: fixed;
        top: 30px;
        right: 0;
        padding: 20px;
        background-color: white; /* White background for image container */
        border-radius: 0 0 0 10px; /* Add rounded corners to bottom left */
    }
    .footer {
        position: fixed;
        bottom: 0;
        width: 100%;
        text-align: center;
        padding: 10px;
    }
    .footer p {
    margin: 0;
    }
    </style>
    """,
    unsafe_allow_html=True
)

# Footer
st.markdown("""
            <div class="footer">
                <p>©Novita Nur Alifah</p>
             </div> 
    """, unsafe_allow_html=True)
    
# Streamlit UI
def predict_url(url, model):
    features = FeatureExtraction(url).parse_url()
    features = np.array(features).reshape(1, -1)
    prediction = model.predict(features)
    return "Phishing" if prediction[0] == 1 else "Legitimate"

with st.sidebar:
    selected = option_menu("Menu", ["URL Detection", "Feature Explanation", "FAQ"], 
                           icons=["search", "star", "question"], 
                           menu_icon="cast", default_index=0)

if selected == "URL Detection":
    st.markdown("""
    <div style='display: flex; align-items: center; gap: 15px;'>
        <img src='https://encrypted-tbn0.gstatic.com/images?q=tbn:ANd9GcR_-W23r2Vc1GONasT-OEGAzElL3cwhkCHv-g&s' width='70'>
        <h1 style='margin: 0;'>Phishing Detection URL</h1>
    </div>
""", unsafe_allow_html=True)

    url = st.text_input("Enter URL:", "")

    st.button("Detect")

    # Perform feature extraction
    obj = FeatureExtraction(url)
    x = np.array(obj.getFeaturesList()).reshape(1, 30)
    # Predict using the model
    y_pred = gbc.predict(x)[0]
    y_pro_phishing = gbc.predict_proba(x)[0, 0]
    y_pro_non_phishing = gbc.predict_proba(x)[0, 1]
    
    # Display prediction result
    if y_pred == 1:
        st.success(f"The URL '{url}' is {y_pro_phishing * 100:.2f}% safe.")
    else:
        st.error(f"The URL '{url}' is {y_pro_non_phishing * 100:.2f}% unsafe.")


elif selected == "Feature Explanation":
    st.header("Fitur - Fitur")
    st.write("Penjelasan untuk setiap fitur yang digunakan dalam model..")
    st.write("1. **Using IP**: Menggunakan alamat IP adalah tanda tidak aman. URL yang aman menggunakan nama domain")
    st.write("2. **Long URL**: URL yang sangat panjang cenderung tidak aman.")
    st.write("3. **Short URL**: Mengecek apakah URL menggunakan layanan pemendek URL (seperti bit.ly)?")
    st.write("Jika ya, maka tidak aman, jika tidak, maka aman.")
    st.write("4. **Symbol**: Mengandung simbol '@' adalah tanda tidak aman.")
    st.write("5. **Redirecting**: Memeriksa apakah URL berisi '//' setelah 'http://' atau 'https://'.")
    st.write("Jika iya, maka aman. Jika tidak, maka tidak aman")
    st.write("6. **Prefix/Suffix**: Domain yang mengandung tanda '-' adalah tanda tidak aman.")
    st.write("7. **SubDomains**: Banyak subdomain adalah tanda tidak aman.")
    st.write("8. **Https**: Menggunakan HTTPS adalah tanda keamanan.")
    st.write("9. **Domain Registration Length**: Domain yang terdaftar lebih dari 1 tahun adalah tanda aman.")
    st.write("10. **Favicon**: Favicon yang berasal dari domain yang sama adalah tanda aman.")
    st.write("11. **Non-Standard Port**:  Menggunakan port yang tidak standar adalah tanda tidak aman.")
    st.write("12. **HTTPS Domain URL**: Memeriksa apakah domain berisi HTTPS.")
    st.write("13. **Request URL**: Persentase URL eksternal dalam tag HTML harus rendah untuk menjadi aman.")
    st.write("14. **Anchor URL**: Persentase link anchor yang mengarah ke luar domain harus rendah untuk menjadi aman.")
    st.write("15. **Links in Script Tags**: Persentase link dalam tag script yang mengarah ke luar domain harus rendah untuk menjadi aman.")
    st.write("16. **Server Form Handler**: Action URL dalam form yang mengarah ke domain yang sama adalah tanda aman.")
    st.write("17. **Info Email**: Memeriksa keberadaan informasi email yang mencurigakan.")
    st.write("18. **Abnormal URL**: Jika URL tidak menunjukkan anomali atau ketidaksesuaian, maka aman.")
    st.write("19. **Website Forwarding**: Menganalisis riwayat pengalihan HTTP untuk melihat berapa kali URL dialihkan.")
    st.write("- Aman: Jika URL tidak mengalami pengalihan atau hanya mengalami satu kali pengalihan.")
    st.write("- Sedang: Jika URL mengalami dua hingga empat kali pengalihan.")
    st.write("- Tidak Aman: Jika URL mengalami lebih dari empat kali pengalihan, yang bisa menunjukkan upaya untuk menyembunyikan sumber asli.")
    st.write("20. **Status Bar Customization**: Memeriksa apakah bilah status disesuaikan..")
    st.write("21. **Disable Right Click**: Memeriksa apakah klik kanan dinonaktifkan.")
    st.write("22. **Using Popup Window**: Memeriksa apakah halaman menggunakan jendela popup.")
    st.write("23. **IframeRedirection** : Memeriksa apakah halaman berisi iframe.")
    st.write("24. **Age of Domain**: Memeriksa usia domain.")
    st.write("25. **DNSRecordin** : Memeriksa usia domain dalam catatan DNS.")
    st.write("26. **Web Traffic**: emeriksa peringkat lalu lintas situs web menggunakan Alexa.")
    st.write("27. **Page Rank**: Memeriksa Google PageRank.")
    st.write("28. **GoogleIndex** : Memeriksa apakah URL diindeks oleh Google.")
    st.write("29. **LinksPointingToPage** : Memeriksa jumlah tautan yang menunjuk ke halaman.")
    st.write("30. **StatsReport** : Memeriksa apakah URL atau IP-nya cocok dengan pola berbahaya yang diketahui.")
    
elif selected == "FAQ":
    st.header("Frequently Asked Question")
    st.write("**1. Apa itu phishing?**")
    st.write("Jawaban: Phishing adalah tindakan penipuan di mana pelaku berpura-pura menjadi entitas tepercaya untuk mencuri informasi sensitif seperti kata sandi, nomor kartu kredit, atau data pribadi lainnya. Pelaku biasanya menggunakan email, pesan teks, atau situs web palsu untuk menipu korban.")
    st.write("**2. Bagaimana cara kerja pendeteksi phishing ini?**")
    st.write("Jawaban: Pendeteksi phishing ini menggunakan model machine learning yang telah dilatih dengan berbagai fitur URL untuk mengidentifikasi apakah sebuah URL aman atau berbahaya. Model ini menganalisis elemen-elemen seperti panjang URL, jumlah subdomain, dan pola tertentu yang sering muncul dalam URL phishing.")
    st.write("**3. Apakah hasil deteksi selalu akurat?**")
    st.write("Jawaban: Meskipun model kami telah dilatih untuk memberikan hasil yang akurat, tidak ada sistem yang sempurna. Hasil deteksi sebaiknya digunakan sebagai referensi tambahan dan tidak menggantikan kebijakan keamanan yang baik. Selalu periksa URL dengan hati-hati dan hindari mengklik tautan yang mencurigakan.")
    st.write("**4. Apakah situs web ini bisa mendeteksi semua jenis phishing?**")
    st.write("Jawaban: Situs web ini dirancang untuk mendeteksi phishing URL aman atau tidak, namun tidak ada sistem yang dapat mendeteksi semua serangan dengan sempurna. Kami terus meningkatkan model kami untuk memperbaiki akurasi deteksi.")
    st.write("**5. Bagaimana saya bisa melindungi diri dari serangan phishing?**")
    st.write("Jawaban: Beberapa cara untuk melindungi diri dari serangan phishing antara lain:")
    st.write("      a. Jangan klik tautan dalam email atau pesan teks yang mencurigakan.")
    st.write("      b. Verifikasi URL sebelum memasukkan informasi pribadi.")
    st.write("      c. Gunakan perangkat lunask keamanan yang andal dan selalu perbarui.")
    st.write("      d. Aktifkan otentikasi dua faktor (2FA) di akun online Anda.")
    st.write("      e. Selalu waspada terhadap email atau pesan yang meminta informasi sensitif.")
    
       
