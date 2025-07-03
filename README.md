# IP_PCAP_Analyzer
Proje amaci

  Belirli bir IP adresine ait paketleri listeler
  Paketlerin zaman, kaynak/hedef IP, port, protokol ve boyut bilgilerini gösterir
  Protokol ve port dağılımı gibi istatistikler sunar
  Hem .pcap hem de .pcapng dosyalarını destekler


Gereksinimler 

  Python 3.x
  Pandas
  Scapy

Bilgisayarinizda python kurulu degil ise 
  https://www.python.org/
sitesinden kurulum saglayabilirsiniz 

Bilgisayarinizda pandas kutuphanesi kurulu degil ise terminalde 
  pip install pandas 
yazarak kurulum saglayabilirsiniz 

Bilgisayarinizda scapy kutuphanesi kurulu degil ise terminalde 
  pip install scapy 
yazarak kurulum saglayabilirsiniz 

Calistirma 

  Derleyici uzerinden kodu calistirdiktan sonra analiz etmek istediginiz pcap veya pcapng dosyasini terminal kismina suruklemeniz yeterli
  takip etmek istediginiz ip adresini yazdiktan sonra analizi yapip cikti verecektir.
