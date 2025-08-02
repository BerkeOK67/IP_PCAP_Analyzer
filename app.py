
from flask import Flask, jsonify, render_template, request
import pandas as pd
import csv
import network_sniffer_cohere_API as ns_api
import os


app = Flask(__name__)

@app.route("/")
def home():
    return render_template("index.html")

@app.route("/data")
def get_data():
    """CSV'den son verileri getir"""
    try:
        df = pd.read_csv("traffic_log.csv",encoding="utf-8")
        if df.empty:
            return jsonify({"error": "No data available"})
        
        # Tüm kayıtları getir (limit yok)
        recent_data = df.to_dict('records')
        
        # İstatistikler
        stats = {
            "total_packets": len(df),
            "normal_count": len(df[df["Local Label"] == "Normal"]),
            "anomalous_count": len(df[df["Local Label"] == "Anomalous"]),
            "mean_size": df["Packet Size"].mean(),
            "std_size": df["Packet Size"].std()
        }
        
        return jsonify({
            "recent_data": recent_data,
            "stats": stats,
            "api_wait_time": get_api_wait_time_from_file()
        })
    except Exception as e:
        return jsonify({"error": str(e)})

@app.route("/data/check")
def check_new_data():
    """Frontend'den gelen son bilinen timestamp ile CSV'deki en son satırı karşılaştır."""
    try:
        last_known = request.args.get('last_timestamp', None)
        df = pd.read_csv("traffic_log.csv", encoding="utf-8")
        if df.empty or last_known is None:
            return jsonify({"new_data": False})
        last_csv = str(df.iloc[-1]["Timestamp"])
        return jsonify({"new_data": last_csv != last_known, "latest_timestamp": last_csv})
    except Exception as e:
        return jsonify({"error": str(e), "new_data": False})

@app.route("/reset", methods=["POST"])
def reset_data():
    """CSV dosyasını sıfırla"""
    try:
        # CSV dosyasını temizle
        with open("traffic_log.csv", "w", newline="") as f:
            csv.writer(f).writerow([
                "Timestamp",
                "IP Source", 
                "IP Destination",
                "Source Port",
                "Destination Port",
                "Protocol",
                "Packet Size",
                "Local Label",
                "AI Label",
                "Src Country",
                "Src City",
            ])
        
        return jsonify({"success": True, "message": "Live traffic data reset successfully!"})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


def get_api_wait_time_from_file():
    try:
        with open('api_wait_time.txt', 'r') as f:
            return int(f.read().strip())
    except Exception:
        return 0


if __name__ == "__main__":
    app.run(debug=True)
