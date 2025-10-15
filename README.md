# CIC-IoMT-2024 Veri Seti K-Means Kümeleme Analizi 

## 📋 Proje Hakkında

Bu proje, **CIC-IoMT-2024 (Canadian Institute for Cybersecurity - Internet of Medical Things)** veri seti üzerinde **K-Means kümeleme algoritması** kullanılarak IoMT (Tıbbi Nesnelerin İnterneti) cihazlarına yönelik siber saldırıların tespit edilmesi ve sınıflandırılmasını amaçlamaktadır.

### 🎯 Proje Amacı

IoMT cihazları sağlık sektöründe kritik öneme sahip olup, bu cihazlara yönelik siber saldırılar hasta güvenliğini ve veri gizliliğini tehdit etmektedir. Bu çalışma, **denetimsiz öğrenme (unsupervised learning)** yöntemleri kullanarak:

- Farklı saldırı türlerinin otomatik olarak gruplandırılması
- Normal ve anormal ağ trafiği davranışlarının ayrıştırılması
- MQTT protokolü saldırılarının detaylı analizi
- Genel ve MQTT-özel saldırı kategorilerinin performans karşılaştırması

---

## 📊 Veri Seti Bilgileri

**CIC-IoMT-2024 Veri Seti**, gerçekçi IoMT ortamında toplanan ve çeşitli siber saldırı senaryolarını içeren kapsamlı bir veri setidir.

#### Protokoller:
- 📡 **WiFi ve MQTT**: HTTP/HTTPS, MQTT mesajlaşma protokolü
- 🔵 **Bluetooth**: BLE (Bluetooth Low Energy) iletişimi

#### Saldırı Kategorileri:

| Kategori | Alt Kategoriler | Açıklama |
|----------|----------------|----------|
| **MQTT Saldırıları** | DDoS-Connect_Flood, DDoS-Publish_Flood, DoS-Connect_Flood, DoS-Publish_Flood, Malformed_Data | MQTT protokolüne özgü saldırı türleri |
| **TCP/IP Saldırıları** | DDoS, DoS | Geleneksel ağ katmanı saldırıları |
| **ARP Spoofing** | - | Adres çözümleme protokolü saldırıları |
| **Reconnaissance** | - | Keşif ve bilgi toplama saldırıları |
| **Benign** | - | Normal, zararsız trafik |

#### Veri Özellikleri:
- **Toplam Özellik Sayısı**: 45 ağ akış özellikleri
- **Örnek Sayısı**: 75,000+ etiketli örnek (dengeli dağılım)
- **Veri Formatı**: CSV ve PCAP dosyaları

---

## 🔬 Gerçekleştirilen Analizler

### 1️⃣ Genel Kategori Sınıflandırması (codes_3)

**K-Means kümeleme algoritması** kullanılarak **tüm saldırı kategorilerinin** analizi.

#### 📌 Parametreler:
- **Veri Boyutu**: 75,130 örnek
- **Özellik Sayısı**: 45
- **Kategori Sayısı**: 8
  - ARP_Spoofing
  - Benign
  - MQTT_DDoS
  - MQTT_DoS
  - MQTT_Malformed
  - Reconnaissance
  - TCP_IP_DDoS
  - TCP_IP_DoS
- **Optimal Küme Sayısı**: 13
- **Hedef Örnek/Kategori**: 10,000 (dengeli dağılım)

#### 📊 Performans Metrikleri:
```
✓ Silhouette Score:          0.4456
✓ Adjusted Rand Index (ARI): 0.4592
✓ Normalized Mutual Info:    0.6103
✓ Calinski-Harabasz Score:   9726.08
✓ Davies-Bouldin Score:      1.1360
✓ Genel Saflık (Purity):     61.84%
```

#### 🎯 Önemli Bulgular:
- **En iyi küme**: Küme 8 (Reconnaissance) → %100 saflık
- **En büyük küme**: Küme 3 (MQTT_DoS) → 22,668 örnek
- **Karışan kategoriler**: TCP_IP_DDoS ve TCP_IP_DoS (birbirine benzer)
- **Performans değerlendirmesi**: Orta düzey - K-Means algoritması genel kategorilerde makul performans gösterdi

#### 📁 Çıktılar:
```
codes_3/
├── kmeans_clustering_analysis.py          # Ana analiz scripti
├── kmeans_clustering_results.png          # 9 panelli detaylı görselleştirme
├── labeled_vs_clustered_comparison.png    # Etiketli vs kümelenmiş karşılaştırma
├── kmeans_clustering_report.txt           # Detaylı metin raporu
├── kmeans_clustering_results.csv          # Tam veri seti + küme atamaları
└── cluster_statistics.csv                 # Küme istatistik özeti
```

---

### 2️⃣ MQTT Alt Kategorileri Detaylı Analizi (codes_5)

**MQTT protokolüne özgü** detaylı kümeleme analizi - Alt kategorilerin ayrımı.

#### 📌 Parametreler:
- **Veri Boyutu**: 25,000 örnek
- **Özellik Sayısı**: 45
- **MQTT Alt Kategorisi**: 5
  - MQTT-DDoS-Connect_Flood
  - MQTT-DDoS-Publish_Flood
  - MQTT-DoS-Connect_Flood
  - MQTT-DoS-Publish_Flood
  - MQTT-Malformed_Data
- **Optimal Küme Sayısı**: 8
- **Hedef Örnek/Kategori**: 5,000 (dengeli dağılım)

#### 📊 Performans Metrikleri:
```
✓ Silhouette Score:          0.3502
✓ Adjusted Rand Index (ARI): 0.5066
✓ Normalized Mutual Info:    0.6240
✓ Homogeneity Score:         0.5909
✓ Completeness Score:        0.6610
✓ V-Measure Score:           0.6240
✓ Fowlkes-Mallows Index:     0.6346
✓ Calinski-Harabasz Score:   4242.61
✓ Davies-Bouldin Score:      1.1159
✓ Genel Saflık (Purity):     69.52%
```

#### 🎯 Önemli Bulgular:
- 🌟 **MQTT-Malformed_Data mükemmel ayrıştı**: 3 küme %98-100 saflıkla
- 📈 **Genel kategorilerden daha iyi performans**: %69.5 vs %61.8 saflık
- 🔍 **En önemli özellikler** (Feature Importance):
  1. IAT (Inter-Arrival Time)
  2. fin_count
  3. Tot size
  4. Min
  5. Header_Length
- 📊 **İstatistiksel Anlamlılık**: F-statistic = 4242.49, p < 0.001 (Evet)
- 🔄 **Küme Kararlılığı**: 0.9628 ± 0.0215 (Çok yüksek)
- ⚠️ **Zorluk**: Connect_Flood ve Publish_Flood arasında kısmi karışıklık

#### 📁 Çıktılar:
```
codes_5/
├── mqtt_subcategories_analysis.py               # MQTT detaylı analiz scripti
├── mqtt_labeled_data_visualization.png          # Etiketli veri keşfi (6 panel)
├── mqtt_clustering_results_visualization.png    # Kümeleme sonuç görseli (6 panel)
├── mqtt_clustering_results.png                  # Ana sonuç grafikleri (9 panel)
├── mqtt_advanced_visualizations.png             # t-SNE, UMAP, dendrogram
├── mqtt_clustering_report.txt                   # MQTT detaylı raporu
├── mqtt_clustering_results.csv                  # MQTT veri + küme atamaları
└── mqtt_cluster_statistics.csv                  # MQTT küme istatistikleri
```

---

## 📊 Sonuçlar ve Karşılaştırma

### codes_3 vs codes_5 Performans Karşılaştırması

| Metrik | codes_3 (Genel) | codes_5 (MQTT) | Kazanan |
|--------|-----------------|----------------|---------|
| **Saflık** | 61.84% | **69.52%** | 🏆 codes_5 |
| **Silhouette** | **0.4456** | 0.3502 | 🏆 codes_3 |
| **ARI** | 0.4592 | **0.5066** | 🏆 codes_5 |
| **NMI** | 0.6103 | **0.6240** | 🏆 codes_5 |
| **Küme Sayısı** | 13 | 8 | - |
| **Veri Boyutu** | 75,130 | 25,000 | - |
| **Kategori Sayısı** | 8 | 5 | - |

### 🎯 Temel Bulgular

1. ✅ **MQTT-özel analiz daha başarılı**: Alt kategorilere odaklanmak %7.7 saflık artışı sağladı
2. ✅ **Malformed Data mükemmel**: MQTT-Malformed_Data %98+ saflıkla tespit edildi
3. ⚠️ **DDoS/DoS karışıklığı**: Hem genel hem MQTT'de DoS ve DDoS birbirine karıştı
4. ✅ **İstatistiksel güvenilirlik**: Her iki analiz de istatistiksel olarak anlamlı (p < 0.001)
5. 📊 **Küme kararlılığı yüksek**: MQTT analizi %96 kararlılık gösterdi

### 🔍 Özellik Önemlilik Analizi (codes_5)

**En ayırt edici özellikler:**

| Sıra | Özellik | F-Score | Mutual Information |
|------|---------|---------|-------------------|
| 1 | syn_count | 12039.06 | 0.9013 |
| 2 | syn_flag_number | 10865.71 | - |
| 3 | HTTPS | 9588.47 | - |
| 4 | IAT | - | **1.6053** |
| 5 | fin_count | - | 1.0300 |

---

## 📁 Proje Yapısı

```
tasarım_proje_cıc_ıot/
│
├── CICIoMT2024/                          # 📦 Veri seti (gitignore'da)
│   ├── Bluetooth/                        
│   │   ├── attacks/
│   │   └── profiling/
│   └── WiFI_and_MQTT/                    
│       ├── attacks/
│       │   ├── csv/
│       │   │   ├── train/                # 51 CSV dosyası
│       │   │   └── test/                 # 21 CSV dosyası
│       │   └── pcap/
│       └── profiling/
│
├── codes_3/                              # 🎯 Genel Kategori Analizi
│   ├── kmeans_clustering_analysis.py     # Ana script (753 satır)
│   ├── kmeans_clustering_results.png     
│   ├── labeled_vs_clustered_comparison.png
│   ├── kmeans_clustering_report.txt      
│   ├── kmeans_clustering_results.csv     
│   └── cluster_statistics.csv            
│
├── codes_5/                              # 🎯 MQTT Alt Kategori Analizi
│   ├── mqtt_subcategories_analysis.py    # MQTT script (1205 satır)
│   ├── mqtt_labeled_data_visualization.png
│   ├── mqtt_clustering_results_visualization.png
│   ├── mqtt_clustering_results.png
│   ├── mqtt_advanced_visualizations.png  
│   ├── mqtt_clustering_report.txt
│   ├── mqtt_clustering_results.csv       
│   └── mqtt_cluster_statistics.csv       
│
├── farklı_algoritma/                     # 📚 Ek: GMM Analizleri (Opsiyonel)
│   ├── gmm_5/                            
│   ├── gmm_10/                           
│   └── gmm_5vs10/                        
│
├── diğer/                                # 📂 Arşiv klasörü
│   ├── codes_s/                          # Eski denemeler
│   ├── EDA/                              # Keşifsel veri analizi
│   └── sunum_görseller/                  # Sunum görselleri
│
├── README.md                             # 📖 Bu dosya
├── requirements.txt                      # 📦 Python gereksinimleri
└── .gitignore                            # 🚫 Git dışlama dosyası
```

---

## 🚀 Kurulum ve Kullanım

### Gereksinimler

Python 3.8+ gereklidir.

```bash
pip install -r requirements.txt
```

**Ana Kütüphaneler:**
- pandas >= 1.5.0
- numpy >= 1.23.0
- matplotlib >= 3.6.0
- seaborn >= 0.12.0
- scikit-learn >= 1.2.0
- scipy >= 1.9.0
- plotly >= 5.11.0

**Opsiyonel** (gelişmiş görselleştirmeler için):
```bash
pip install umap-learn
```

---

### Kullanım

#### 1️⃣ Genel Kategori Analizi (codes_3)

```bash
cd codes_3
python kmeans_clustering_analysis.py
```

**Çıktılar:**
- Optimal küme sayısı belirleme (Elbow method, Silhouette)
- K-Means kümeleme (13 küme)
- PCA 2D görselleştirme
- Küme-etiket karışıklık matrisi
- Performans metrikleri
- Detaylı rapor ve CSV dosyaları

**Süre:** ~5-10 dakika (veri boyutuna göre)

---

#### 2️⃣ MQTT Alt Kategori Analizi (codes_5)

```bash
cd codes_5
python mqtt_subcategories_analysis.py
```

**Çıktılar:**
- Etiketli veri keşifsel analizi
- MQTT-özel kümeleme (8 küme)
- t-SNE, UMAP, PCA görselleştirmeleri
- Hierarchical clustering dendrogram
- Özellik önemlilik analizi
- İstatistiksel anlamlılık testleri
- Bootstrap küme kararlılık analizi
- MQTT-özel detaylı rapor

**Süre:** ~10-15 dakika (t-SNE/UMAP hesaplamaları)

---

## 🔬 Metodoloji

### Veri Ön İşleme

1. **Veri Yükleme**: CSV dosyalarından etiket çıkarma
2. **Dengeli Örnekleme**: Her kategori için eşit sayıda örnek (5,000-10,000)
3. **Temizleme**: 
   - Eksik değerler → Medyan ile doldurma
   - Sonsuz değerler → NaN'a çevir + medyan
4. **Normalizasyon**: StandardScaler ile özellik standardizasyonu
5. **Etiket Kodlama**: String etiketler → Sayısal kodlar

### K-Means Kümeleme Algoritması

```python
# Optimal k bulma
for k in range(2, max_clusters):
    kmeans = KMeans(n_clusters=k, random_state=42, n_init=10)
    silhouette_scores.append(silhouette_score(X, kmeans.labels_))

optimal_k = k_range[np.argmax(silhouette_scores)]

# K-Means uygulama
kmeans = KMeans(n_clusters=optimal_k, random_state=42, n_init=10)
cluster_labels = kmeans.fit_predict(scaled_features)
```

**Parametreler:**
- `n_clusters`: Silhouette score ile otomatik belirleme
- `random_state=42`: Tekrarlanabilirlik
- `n_init=10`: Farklı merkezlerle 10 deneme

### Değerlendirme Metrikleri

#### Kümeleme Kalitesi (Gerçek etiket gerekmez):
- **Silhouette Score** (-1 ile 1): Küme ayrımı kalitesi
- **Calinski-Harabasz Score**: Küme yoğunluğu (yüksek = iyi)
- **Davies-Bouldin Score**: Küme benzerliği (düşük = iyi)

#### Etiket Uyumu (Gerçek etiket ile karşılaştırma):
- **Adjusted Rand Index (ARI)** (0-1): Küme-etiket uyumu
- **Normalized Mutual Info (NMI)** (0-1): Bilgi paylaşımı
- **Homogeneity** (0-1): Her küme tek sınıftan mı?
- **Completeness** (0-1): Her sınıf tek kümede mi?
- **V-Measure** (0-1): Homogeneity ve completeness harmonik ortalaması
- **Purity** (%): En baskın etiketin kümedeki oranı

#### İstatistiksel Testler (codes_5):
- **F-testi**: Küme farklılığı anlamlılığı
- **Bootstrap**: Küme kararlılık analizi (10 iterasyon)
- **Feature Importance**: F-test ve Mutual Information

### Görselleştirme Teknikleri

1. **PCA (Principal Component Analysis)**
   - 2D/3D boyut indirgeme
   - Açıklanan varyans: ~20-30%

2. **t-SNE (t-Distributed Stochastic Neighbor Embedding)**
   - Non-linear boyut indirgeme
   - Lokal yapıları korur
   - Perplexity=30, n_iter=1000

3. **UMAP (Uniform Manifold Approximation)**
   - Modern boyut indirgeme
   - Hem lokal hem global yapı
   - n_neighbors=15, min_dist=0.1

4. **Hierarchical Clustering**
   - Ward linkage dendrogram
   - 1000 örnek subsample (performans)

---

## 📈 Görselleştirme Örnekleri

### codes_3 Görselleştirmeleri:
- **9 panelli ana grafik**: Elbow, Silhouette, Calinski-Harabasz, küme/etiket dağılımları, saflık, confusion matrix, metrik karşılaştırması
- **4 panelli karşılaştırma**: PCA gerçek etiketler, PCA kümeler, etiket dağılımı, küme dağılımı

### codes_5 Görselleştirmeleri:
- **6 panelli etiketli veri**: PCA 2D, korelasyon matrisi, pasta grafik, bar grafik, özellik önemlilik, veri özeti
- **6 panelli kümeleme sonuçları**: PCA etiketler, PCA kümeler, confusion matrix, küme dağılımı, küme saflığı (bubble chart), performans özeti
- **9 panelli ana grafik**: Elbow, Silhouette, Calinski-Harabasz, küme/etiket/saflık dağılımları, confusion matrix, metrikler, özet
- **6 panelli gelişmiş**: t-SNE etiketler, t-SNE kümeler, UMAP etiketler, UMAP kümeler, dendrogram, feature importance

---

## 🎓 Akademik Referanslar

1. **CIC-IoMT-2024 Dataset**
   - Canadian Institute for Cybersecurity
   - University of New Brunswick
   - [https://www.unb.ca/cic/datasets/](https://www.unb.ca/cic/datasets/)

2. **K-Means Clustering**
   - MacQueen, J. (1967). "Some methods for classification and analysis of multivariate observations"
   - Arthur, D., & Vassilvitskii, S. (2007). "k-means++: The advantages of careful seeding"

3. **Scikit-learn**
   - Pedregosa et al. (2011). "Scikit-learn: Machine Learning in Python", JMLR 12, pp. 2825-2830

4. **IoMT Security**
   - Williams, P. A., & Woodward, A. J. (2015). "Cybersecurity vulnerabilities in medical devices"
   - Rahman, A. et al. (2020). "Internet of Medical Things: A comprehensive survey"

5. **Clustering Evaluation**
   - Rousseeuw, P. J. (1987). "Silhouettes: A graphical aid to the interpretation and validation of cluster analysis"
   - Hubert, L., & Arabie, P. (1985). "Comparing partitions", Journal of Classification

---

## 💡 Gelecek Çalışmalar

- [ ] Hierarchical clustering (Agglomerative, Divisive) uygulanması
- [ ] DBSCAN ve HDBSCAN ile yoğunluk tabanlı kümeleme
- [ ] Deep learning (Autoencoder) ile özellik öğrenme
- [ ] Gerçek zamanlı saldırı tespit sistemi
- [ ] Bluetooth protokol analizlerinin eklenmesi
- [ ] Ensemble kümeleme yöntemleri

---

## 🤝 Katkıda Bulunma

Bu proje akademik araştırma amaçlı geliştirilmiştir. Katkılarınızı bekliyoruz:

1. Fork yapın
2. Feature branch oluşturun (`git checkout -b feature/AmazingFeature`)
3. Commit yapın (`git commit -m 'Add some AmazingFeature'`)
4. Push edin (`git push origin feature/AmazingFeature`)
5. Pull Request açın

---

## 📝 Lisans

Bu proje akademik ve eğitim amaçlı kullanım içindir. Veri seti kullanımı için CIC-IoMT-2024 lisans koşullarına uyulmalıdır.

---

## 📧 İletişim

Proje hakkında sorularınız için:
- 🐛 **Issues** sekmesinden bildirim oluşturabilirsiniz
- 🌟 Projeyi beğendiyseniz **yıldızlamayı** unutmayın!

---

<div align="center">

### ⚕️ Sağlık Teknolojilerinde Güvenlik ⚕️
### 🛡️ Siber Tehditlere Karşı Makine Öğrenmesi 🛡️

**Made with ❤️ for IoMT Security Research**

---

![Python](https://img.shields.io/badge/Python-3.8+-blue.svg)
![scikit-learn](https://img.shields.io/badge/scikit--learn-1.2+-orange.svg)
![License](https://img.shields.io/badge/License-Academic-green.svg)

</div>

