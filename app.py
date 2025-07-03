from flask import Flask, render_template,request
import os 
from IP_info import pcap_ip_bilgisi_goster
import pandas as pd
import tempfile

app = Flask(__name__)

@app.route("/", methods=["GET","POST"])
def index():
    results = None
    stats = None
    if request.method == 'POST':
        file = request.files['pcapfile']
        ip = request.form['ipaddress']
        if file and ip:
            with tempfile.NamedTemporaryFile(delete=False) as tmp:
                file.save(tmp.name)
                df = pcap_ip_bilgisi_goster(tmp.name, ip, return_df=True)
                if df is not None and not df.empty:
                    results = df.to_html(classes='table table-striped', index=False)
                    stats = {
                        "protokol": df['Protokol_Adi'].value_counts().to_frame().to_html(),
                        "kaynak_port": df['Kaynak_Port'].value_counts().head(3).to_frame().to_html(),
                        "hedef_port": df['Hedef_Port'].value_counts().head(3).to_frame().to_html(),
                        "boyut_ort": f"{df['Paket_Boyutu'].mean():.2f} byte",
                        "boyut_min": f"{df['Paket_Boyutu'].min()} byte",
                        "boyut_max": f"{df['Paket_Boyutu'].max()} byte"
                    }
                else:
                    results = "Bu IP adresine ait paket bulunamadı."
    return render_template('index.html', results=results, stats=stats)

if __name__ == '__main__':
    app.run(debug=True)