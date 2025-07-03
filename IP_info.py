from scapy.layers.inet import IP, TCP, UDP
from scapy.all import rdpcap
import pandas as pd
from datetime import datetime

def pcap_ip_bilgisi_goster(pcap_dosya, hedef_ip):

    #PCAP dosyasından belirli bir IP adresine ait paketleri analiz eder

    paketler = rdpcap(pcap_dosya)
    sonuclar = []
    
    print(f"PCAP dosyası okunuyor: {pcap_dosya}")
    print(f"Aranan IP adresi: {hedef_ip}")

    print("-" * 80)
    
    for i, paket in enumerate(paketler):
        # IP katmanı var mı 
        if IP in paket:
            kaynak_ip = paket[IP].src
            hedef_ip_paket = paket[IP].dst
            
            # Aranan IP adresi bu pakette var mı?
            if kaynak_ip == hedef_ip or hedef_ip_paket == hedef_ip:
                # Zaman bilgisini güvenli şekilde al
                try:
                    if hasattr(paket, 'time'):
                        zaman_str = datetime.fromtimestamp(float(paket.time)).strftime('%Y-%m-%d %H:%M:%S')
                    elif hasattr(paket, 'timestamp'):
                        zaman_str = datetime.fromtimestamp(float(paket.timestamp)).strftime('%Y-%m-%d %H:%M:%S')
                    else:
                        zaman_str = f"Paket_{i+1}"
                except:
                    zaman_str = f"Paket_{i+1}"
                
                paket_bilgi = {
                    'Paket_No': i + 1,
                    'Zaman': zaman_str,
                    'Kaynak_IP': kaynak_ip,
                    'Hedef_IP': hedef_ip_paket,
                    'Protokol': paket[IP].proto,
                    'Paket_Boyutu': len(paket),
                    'TTL': paket[IP].ttl
                }
                
                # TCP/UDP port bilgileri varsa ekle
                if TCP in paket:
                    paket_bilgi['Kaynak_Port'] = paket[TCP].sport
                    paket_bilgi['Hedef_Port'] = paket[TCP].dport
                    paket_bilgi['Protokol_Adi'] = 'TCP'
                elif UDP in paket:
                    paket_bilgi['Kaynak_Port'] = paket[UDP].sport
                    paket_bilgi['Hedef_Port'] = paket[UDP].dport
                    paket_bilgi['Protokol_Adi'] = 'UDP'
                else:
                    paket_bilgi['Protokol_Adi'] = 'Diğer'
                
                sonuclar.append(paket_bilgi)
    
    if sonuclar:
        df = pd.DataFrame(sonuclar)
        print(f"Toplam {len(sonuclar)} paket bulundu:")
        print(df.to_string(index=False))
        
        # İstatistikleri göster
        print("\n" + "-"*130)
        print(" "*25 + "İSTATİSTİKLER")
       
        
        # Protokol dağılımı
        if 'Protokol_Adi' in df.columns:
            print("\nProtokol Dağılımı:")
            print(df['Protokol_Adi'].value_counts())
            print("\nEn çok kullanılan protokoller:")
            print(df['Protokol_Adi'].value_counts().head(3))
            
        
        # Port istatistikleri
        if 'Kaynak_Port' in df.columns:
            print(f"\nEn çok kullanılan kaynak portlar:")
            print(df['Kaynak_Port'].value_counts().head(3))
        
        if 'Hedef_Port' in df.columns:
            print(f"\nEn çok kullanılan hedef portlar:")
            print(df['Hedef_Port'].value_counts().head(3))
        
        # Paket boyutu istatistikleri
        print(f"\nPaket Boyutu İstatistikleri:")
        print(f"Ortalama: {df['Paket_Boyutu'].mean():.2f} byte")
        print(f"En küçük: {df['Paket_Boyutu'].min()} byte")
        print(f"En büyük: {df['Paket_Boyutu'].max()} byte")
        
    else:
        print(f"{hedef_ip} adresine ait paket bulunamadı.")


pcap_dosya = input("PCAP dosyasının adını giriniz veya dosyayı sürükleyiniz: ")  
hedef_ip = input("Analiz etmek istediğiniz IP adresini giriniz: ")   

pcap_ip_bilgisi_goster(pcap_dosya, hedef_ip)
