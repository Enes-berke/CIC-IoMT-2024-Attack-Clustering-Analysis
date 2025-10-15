#!/usr/bin/env python3
"""
CIC-IoMT-2024 K-Means Kümeleme Analizi
======================================

Bu script, etiketli WiFi/MQTT verilerini K-Means kümeleme algoritması ile analiz eder
ve sonuçları gerçek etiketlerle karşılaştırır.

Author: AI Assistant
Date: 2024
"""

import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.cluster import KMeans
from sklearn.preprocessing import StandardScaler
from sklearn.decomposition import PCA
from sklearn.metrics import adjusted_rand_score, normalized_mutual_info_score
from sklearn.metrics import silhouette_score, calinski_harabasz_score, davies_bouldin_score
from sklearn.metrics import confusion_matrix, classification_report
import warnings
from pathlib import Path
import os
from collections import Counter
import plotly.express as px
import plotly.graph_objects as go
from plotly.subplots import make_subplots
import plotly.offline as pyo

warnings.filterwarnings('ignore')

class KMeansAnalyzer:
    def __init__(self, data_path):
        self.data_path = Path(data_path)
        self.data = None
        self.features = None
        self.labels = None
        self.scaled_features = None
        self.kmeans_model = None
        self.cluster_labels = None
        self.results = {}
        
    def load_and_prepare_data(self):
        """Veri dosyalarını yükle ve hazırla"""
        print("=== VERİ YÜKLEME VE HAZIRLAMA ===")
        
        # Train klasöründeki CSV dosyalarını bul
        train_path = self.data_path / "CICIoMT2024" / "WiFI_and_MQTT" / "attacks" / "csv" / "train"
        csv_files = list(train_path.glob("*.csv"))
        
        # Hedef örnek sayıları (dengeli veri seti için)
        target_samples = {
            'TCP_IP_DDoS': 10000,
            'TCP_IP_DoS': 10000,
            'Benign': 10000,
            'MQTT_DDoS': 10000,
            'Reconnaissance': 10000,
            'MQTT_DoS': 10000,
            'ARP_Spoofing': 10000,
            'MQTT_Malformed': 10000
        }
        
        # Dosya isimlerinden etiketleri çıkar ve örnekle
        all_data = []
        label_mapping = {}
        
        for csv_file in csv_files:
            if csv_file.name.startswith('._'):
                continue
                
            try:
                print(f"Yükleniyor: {csv_file.name}")
                df = pd.read_csv(csv_file)
                
                # Dosya isminden etiket çıkar
                filename = csv_file.stem.replace('.pcap', '')
                
                if 'Benign' in filename:
                    label = 'Benign'
                elif 'ARP_Spoofing' in filename:
                    label = 'ARP_Spoofing'
                elif 'MQTT-DDoS' in filename:
                    label = 'MQTT_DDoS'
                elif 'MQTT-DoS' in filename:
                    label = 'MQTT_DoS'
                elif 'MQTT-Malformed' in filename:
                    label = 'MQTT_Malformed'
                elif 'Recon-' in filename:
                    label = 'Reconnaissance'
                elif 'TCP_IP-DDoS' in filename:
                    label = 'TCP_IP_DDoS'
                elif 'TCP_IP-DoS' in filename:
                    label = 'TCP_IP_DoS'
                else:
                    label = 'Other'
                
                # Etiket sütunu ekle
                df['label'] = label
                df['filename'] = filename
                
                # Hedef örnek sayısına göre örnekle
                if label in target_samples:
                    target_count = target_samples[label]
                    current_count = label_mapping.get(label, 0)
                    
                    if current_count < target_count:
                        remaining_needed = target_count - current_count
                        
                        if len(df) <= remaining_needed:
                            # Tüm dosyayı al
                            selected_df = df
                        else:
                            # Rastgele örnekle
                            selected_df = df.sample(n=remaining_needed, random_state=42)
                        
                        all_data.append(selected_df)
                        label_mapping[label] = label_mapping.get(label, 0) + len(selected_df)
                        
                        print(f"  - {label}: {len(selected_df)} örnek eklendi (toplam: {label_mapping[label]})")
                    else:
                        print(f"  - {label}: Yeterli örnek mevcut, atlandı")
                else:
                    print(f"  - {label}: Hedef listede yok, atlandı")
                
            except Exception as e:
                print(f"Hata: {csv_file.name} - {e}")
                continue
        
        if not all_data:
            raise ValueError("Hiç veri yüklenemedi!")
        
        # Tüm verileri birleştir
        self.data = pd.concat(all_data, ignore_index=True)
        print(f"\nToplam veri: {len(self.data)} örnek")
        
        # Etiket dağılımını göster
        print("\nDengeli Etiket Dağılımı:")
        for label, count in sorted(label_mapping.items()):
            percentage = (count / len(self.data)) * 100
            print(f"  - {label}: {count:,} örnek ({percentage:.1f}%)")
        
        self.results['label_distribution'] = label_mapping
        self.results['target_samples'] = target_samples
        return self.data
    
    def prepare_features(self):
        """Özellik matrisini hazırla (PCA kullanmadan)"""
        print("\n=== ÖZELLİK HAZIRLAMA ===")
        
        # Etiket sütunlarını çıkar
        feature_columns = [col for col in self.data.columns if col not in ['label', 'filename']]
        self.features = self.data[feature_columns].copy()
        self.labels = self.data['label'].copy()
        
        print(f"Özellik sayısı: {len(feature_columns)}")
        print(f"Örnek sayısı: {len(self.features)}")
        
        # Eksik değerleri kontrol et ve doldur
        missing_values = self.features.isnull().sum().sum()
        print(f"Eksik değer sayısı: {missing_values}")
        
        if missing_values > 0:
            self.features = self.features.fillna(self.features.median())
            print("Eksik değerler medyan ile dolduruldu")
        
        # Sonsuz değerleri kontrol et
        inf_values = np.isinf(self.features).sum().sum()
        print(f"Sonsuz değer sayısı: {inf_values}")
        
        if inf_values > 0:
            self.features = self.features.replace([np.inf, -np.inf], np.nan)
            self.features = self.features.fillna(self.features.median())
            print("Sonsuz değerler düzeltildi")
        
        # Özellikleri standardize et
        scaler = StandardScaler()
        self.scaled_features = scaler.fit_transform(self.features)
        
        print("Özellikler standardize edildi")
        
        # Etiketleri sayısal değerlere çevir
        unique_labels = sorted(self.labels.unique())
        self.label_to_numeric = {label: i for i, label in enumerate(unique_labels)}
        self.numeric_labels = np.array([self.label_to_numeric[label] for label in self.labels])
        
        print(f"Etiket sayısı: {len(unique_labels)}")
        print(f"Etiketler: {unique_labels}")
        
        self.results['feature_info'] = {
            'n_features': len(feature_columns),
            'n_samples': len(self.features),
            'unique_labels': unique_labels,
            'label_counts': dict(Counter(self.labels))
        }
        
        return self.scaled_features, self.numeric_labels
    
    def visualize_labeled_vs_clustered_data(self):
        """Etiketli veriler vs K-Means kümeleri karşılaştırması"""
        print("\n=== ETİKETLİ VERİ vs KÜMELEME SONUÇLARI KARŞILAŞTIRMASI ===")
        
        # PCA ile boyut azaltma
        pca = PCA(n_components=2, random_state=42)
        pca_result = pca.fit_transform(self.scaled_features)
        
        # Görselleştirme - 2x2 layout
        fig, axes = plt.subplots(2, 2, figsize=(16, 12))
        
        # 1. PCA - Gerçek Etiketler
        unique_labels = sorted(self.labels.unique())
        colors = plt.cm.tab10(np.linspace(0, 1, len(unique_labels)))
        
        for i, label in enumerate(unique_labels):
            mask = self.labels == label
            axes[0, 0].scatter(pca_result[mask, 0], pca_result[mask, 1], 
                             c=[colors[i]], label=label, alpha=0.7, s=20)
        
        axes[0, 0].set_title('Gerçek Etiketli Veriler - PCA (2D)', fontsize=14, fontweight='bold')
        axes[0, 0].set_xlabel(f'PC1 ({pca.explained_variance_ratio_[0]:.2%})')
        axes[0, 0].set_ylabel(f'PC2 ({pca.explained_variance_ratio_[1]:.2%})')
        axes[0, 0].legend(bbox_to_anchor=(1.05, 1), loc='upper left', fontsize=8)
        axes[0, 0].grid(True, alpha=0.3)
        
        # 2. PCA - K-Means Kümeleri
        cluster_colors = plt.cm.tab10(np.linspace(0, 1, self.kmeans_model.n_clusters))
        
        for i in range(self.kmeans_model.n_clusters):
            mask = self.cluster_labels == i
            axes[0, 1].scatter(pca_result[mask, 0], pca_result[mask, 1], 
                             c=[cluster_colors[i]], label=f'Küme {i}', alpha=0.7, s=20)
        
        axes[0, 1].set_title('K-Means Kümeleri - PCA (2D)', fontsize=14, fontweight='bold')
        axes[0, 1].set_xlabel(f'PC1 ({pca.explained_variance_ratio_[0]:.2%})')
        axes[0, 1].set_ylabel(f'PC2 ({pca.explained_variance_ratio_[1]:.2%})')
        axes[0, 1].legend(bbox_to_anchor=(1.05, 1), loc='upper left', fontsize=8)
        axes[0, 1].grid(True, alpha=0.3)
        
        # 3. Gerçek Etiket Dağılımı
        label_counts = Counter(self.labels)
        bars1 = axes[1, 0].bar(range(len(label_counts)), label_counts.values(), 
                              color=colors[:len(label_counts)], alpha=0.8)
        axes[1, 0].set_title('Gerçek Etiket Dağılımı', fontsize=14, fontweight='bold')
        axes[1, 0].set_xlabel('Etiketler')
        axes[1, 0].set_ylabel('Örnek Sayısı')
        axes[1, 0].set_xticks(range(len(label_counts)))
        axes[1, 0].set_xticklabels(label_counts.keys(), rotation=45)
        axes[1, 0].grid(True, alpha=0.3)
        
        # Bar üzerine sayıları ekle
        for i, bar in enumerate(bars1):
            height = bar.get_height()
            axes[1, 0].text(bar.get_x() + bar.get_width()/2., height + height*0.01,
                           f'{int(height):,}', ha='center', va='bottom', fontweight='bold')
        
        # 4. K-Means Küme Dağılımı
        cluster_counts = Counter(self.cluster_labels)
        bars2 = axes[1, 1].bar(cluster_counts.keys(), cluster_counts.values(), 
                              color=cluster_colors[:len(cluster_counts)], alpha=0.8)
        axes[1, 1].set_title('K-Means Küme Dağılımı', fontsize=14, fontweight='bold')
        axes[1, 1].set_xlabel('Küme ID')
        axes[1, 1].set_ylabel('Örnek Sayısı')
        axes[1, 1].grid(True, alpha=0.3)
        
        # Bar üzerine sayıları ekle
        for bar in bars2:
            height = bar.get_height()
            axes[1, 1].text(bar.get_x() + bar.get_width()/2., height + height*0.01,
                           f'{int(height):,}', ha='center', va='bottom', fontweight='bold')
        
        plt.tight_layout()
        plt.savefig('/Volumes/KIOXIA/tasarım_proje_cıc_ıot/codes_3/codes_3/labeled_vs_clustered_comparison.png', 
                   dpi=300, bbox_inches='tight')
        plt.show()
        
        print("Etiketli veri vs Kümeler karşılaştırması kaydedildi: labeled_vs_clustered_comparison.png")
        
        # Sonuçları sakla
        self.pca_result = pca_result
        self.pca = pca
        
        # Detaylı analiz raporu
        self.print_detailed_comparison_analysis()
    
    def print_detailed_comparison_analysis(self):
        """Detaylı karşılaştırma analizi yazdır"""
        print("\n=== DETAYLI KARŞILAŞTIRMA ANALİZİ ===")
        
        # Gerçek etiket dağılımı
        label_counts = Counter(self.labels)
        print("\nGERÇEK ETİKET DAĞILIMI:")
        total_samples = len(self.labels)
        for label, count in sorted(label_counts.items()):
            percentage = (count / total_samples) * 100
            print(f"  {label}: {count:,} örnek ({percentage:.2f}%)")
        
        # K-Means küme dağılımı
        cluster_counts = Counter(self.cluster_labels)
        print("\nK-MEANS KÜME DAĞILIMI:")
        for cluster_id, count in sorted(cluster_counts.items()):
            percentage = (count / total_samples) * 100
            print(f"  Küme {cluster_id}: {count:,} örnek ({percentage:.2f}%)")
        
        # Küme-etiket analizi
        print("\nKÜME-ETİKET ANALİZİ:")
        for cluster_id in range(self.kmeans_model.n_clusters):
            cluster_mask = self.cluster_labels == cluster_id
            cluster_labels = self.labels[cluster_mask]
            
            label_counts_in_cluster = Counter(cluster_labels)
            dominant_label = label_counts_in_cluster.most_common(1)[0][0]
            dominant_count = label_counts_in_cluster[dominant_label]
            total_in_cluster = len(cluster_labels)
            purity = dominant_count / total_in_cluster
            
            print(f"\n  Küme {cluster_id} ({total_in_cluster:,} örnek):")
            print(f"    En baskın etiket: {dominant_label} ({dominant_count:,} örnek)")
            print(f"    Saflık: {purity:.4f}")
            print(f"    Tüm etiketler: {dict(label_counts_in_cluster)}")
        
        # Performans metrikleri
        print(f"\nPERFORMANS METRİKLERİ:")
        print(f"  Silhouette Score: {self.results['clustering_metrics']['silhouette_score']:.4f}")
        print(f"  Adjusted Rand Index: {self.results['clustering_metrics']['adjusted_rand_index']:.4f}")
        print(f"  Normalized Mutual Info: {self.results['clustering_metrics']['normalized_mutual_info']:.4f}")
        print(f"  Genel Saflık: {self.results['overall_purity']:.4f}")
        
        # PCA bilgileri
        print(f"\nPCA BİLGİLERİ:")
        print(f"  PC1 açıklanan varyans: {self.pca.explained_variance_ratio_[0]:.2%}")
        print(f"  PC2 açıklanan varyans: {self.pca.explained_variance_ratio_[1]:.2%}")
        print(f"  Toplam açıklanan varyans: {self.pca.explained_variance_ratio_.sum():.2%}")
    
    def find_optimal_clusters(self):
        """Optimal küme sayısını bul"""
        print("\n=== OPTİMAL KÜME SAYISI BULMA ===")
        
        # Elbow method ve silhouette score kullanarak optimal k'yı bul
        max_clusters = min(20, len(np.unique(self.numeric_labels)) + 5)
        inertias = []
        silhouette_scores = []
        calinski_scores = []
        davies_bouldin_scores = []
        
        k_range = range(2, max_clusters + 1)
        
        for k in k_range:
            kmeans = KMeans(n_clusters=k, random_state=42, n_init=10)
            cluster_labels = kmeans.fit_predict(self.scaled_features)
            
            inertias.append(kmeans.inertia_)
            silhouette_scores.append(silhouette_score(self.scaled_features, cluster_labels))
            calinski_scores.append(calinski_harabasz_score(self.scaled_features, cluster_labels))
            davies_bouldin_scores.append(davies_bouldin_score(self.scaled_features, cluster_labels))
        
        # Optimal k'yı seç (silhouette score'a göre)
        optimal_k = k_range[np.argmax(silhouette_scores)]
        
        print(f"Optimal küme sayısı: {optimal_k}")
        print(f"Silhouette Score: {max(silhouette_scores):.4f}")
        
        self.results['optimal_k'] = optimal_k
        self.results['k_range'] = list(k_range)
        self.results['inertias'] = inertias
        self.results['silhouette_scores'] = silhouette_scores
        self.results['calinski_scores'] = calinski_scores
        self.results['davies_bouldin_scores'] = davies_bouldin_scores
        
        return optimal_k
    
    def perform_kmeans_clustering(self, n_clusters=None):
        """K-Means kümeleme uygula"""
        print("\n=== K-MEANS KÜMELEME ===")
        
        if n_clusters is None:
            n_clusters = self.results['optimal_k']
        
        # K-Means modelini eğit
        self.kmeans_model = KMeans(n_clusters=n_clusters, random_state=42, n_init=10)
        self.cluster_labels = self.kmeans_model.fit_predict(self.scaled_features)
        
        print(f"K-Means kümeleme tamamlandı (k={n_clusters})")
        
        # Küme istatistikleri
        cluster_counts = Counter(self.cluster_labels)
        print("\nKüme Dağılımı:")
        for cluster_id, count in sorted(cluster_counts.items()):
            print(f"  Küme {cluster_id}: {count} örnek")
        
        # Gerçek etiketlerle karşılaştır
        self.evaluate_clustering()
        
        return self.cluster_labels
    
    def evaluate_clustering(self):
        """Kümeleme sonuçlarını değerlendir"""
        print("\n=== KÜMELEME DEĞERLENDİRME ===")
        
        # Kümeleme metrikleri
        silhouette_avg = silhouette_score(self.scaled_features, self.cluster_labels)
        calinski_score = calinski_harabasz_score(self.scaled_features, self.cluster_labels)
        davies_bouldin = davies_bouldin_score(self.scaled_features, self.cluster_labels)
        
        print(f"Silhouette Score: {silhouette_avg:.4f}")
        print(f"Calinski-Harabasz Score: {calinski_score:.4f}")
        print(f"Davies-Bouldin Score: {davies_bouldin:.4f}")
        
        # Gerçek etiketlerle karşılaştırma
        ari_score = adjusted_rand_score(self.numeric_labels, self.cluster_labels)
        nmi_score = normalized_mutual_info_score(self.numeric_labels, self.cluster_labels)
        
        print(f"Adjusted Rand Index: {ari_score:.4f}")
        print(f"Normalized Mutual Information: {nmi_score:.4f}")
        
        self.results['clustering_metrics'] = {
            'silhouette_score': silhouette_avg,
            'calinski_harabasz_score': calinski_score,
            'davies_bouldin_score': davies_bouldin,
            'adjusted_rand_index': ari_score,
            'normalized_mutual_info': nmi_score
        }
        
        # Küme-etiket karışıklık matrisi oluştur
        self.create_confusion_analysis()
    
    def create_confusion_analysis(self):
        """Küme ve etiket karışıklık analizi"""
        print("\n=== KÜME-ETİKET ANALİZİ ===")
        
        # Her küme için en baskın etiketi bul
        cluster_label_analysis = {}
        
        for cluster_id in range(self.kmeans_model.n_clusters):
            cluster_mask = self.cluster_labels == cluster_id
            cluster_labels = self.labels[cluster_mask]
            
            label_counts = Counter(cluster_labels)
            dominant_label = label_counts.most_common(1)[0][0]
            dominant_count = label_counts[dominant_label]
            total_in_cluster = len(cluster_labels)
            purity = dominant_count / total_in_cluster
            
            cluster_label_analysis[cluster_id] = {
                'dominant_label': dominant_label,
                'dominant_count': dominant_count,
                'total_samples': total_in_cluster,
                'purity': purity,
                'all_labels': dict(label_counts)
            }
            
            print(f"Küme {cluster_id}:")
            print(f"  En baskın etiket: {dominant_label} ({dominant_count}/{total_in_cluster})")
            print(f"  Saflık: {purity:.4f}")
            print(f"  Tüm etiketler: {dict(label_counts)}")
        
        self.results['cluster_analysis'] = cluster_label_analysis
        
        # Genel saflık
        total_correct = sum([info['dominant_count'] for info in cluster_label_analysis.values()])
        overall_purity = total_correct / len(self.labels)
        print(f"\nGenel Saflık: {overall_purity:.4f}")
        
        self.results['overall_purity'] = overall_purity
    
    def create_visualizations(self):
        """Görselleştirmeler oluştur"""
        print("\n=== GÖRSELLEŞTİRME OLUŞTURMA ===")
        
        # Matplotlib stilini ayarla
        plt.style.use('seaborn-v0_8')
        fig = plt.figure(figsize=(20, 16))
        
        # 1. Optimal k bulma grafikleri
        plt.subplot(3, 3, 1)
        plt.plot(self.results['k_range'], self.results['inertias'], 'bo-')
        plt.xlabel('Küme Sayısı (k)')
        plt.ylabel('Inertia')
        plt.title('Elbow Method - Optimal K Bulma')
        plt.grid(True)
        
        plt.subplot(3, 3, 2)
        plt.plot(self.results['k_range'], self.results['silhouette_scores'], 'ro-')
        plt.xlabel('Küme Sayısı (k)')
        plt.ylabel('Silhouette Score')
        plt.title('Silhouette Score - Optimal K Bulma')
        plt.grid(True)
        
        plt.subplot(3, 3, 3)
        plt.plot(self.results['k_range'], self.results['calinski_scores'], 'go-')
        plt.xlabel('Küme Sayısı (k)')
        plt.ylabel('Calinski-Harabasz Score')
        plt.title('Calinski-Harabasz Score')
        plt.grid(True)
        
        # 2. Küme dağılımı
        plt.subplot(3, 3, 4)
        cluster_counts = Counter(self.cluster_labels)
        plt.bar(cluster_counts.keys(), cluster_counts.values())
        plt.xlabel('Küme ID')
        plt.ylabel('Örnek Sayısı')
        plt.title('Küme Dağılımı')
        
        # 3. Etiket dağılımı
        plt.subplot(3, 3, 5)
        label_counts = Counter(self.labels)
        plt.bar(range(len(label_counts)), label_counts.values())
        plt.xlabel('Etiket')
        plt.ylabel('Örnek Sayısı')
        plt.title('Gerçek Etiket Dağılımı')
        plt.xticks(range(len(label_counts)), label_counts.keys(), rotation=45)
        
        # 4. Küme saflığı
        plt.subplot(3, 3, 6)
        cluster_purities = [self.results['cluster_analysis'][i]['purity'] 
                          for i in range(self.kmeans_model.n_clusters)]
        plt.bar(range(len(cluster_purities)), cluster_purities)
        plt.xlabel('Küme ID')
        plt.ylabel('Saflık')
        plt.title('Küme Saflığı')
        plt.ylim(0, 1)
        
        # 5. Küme-etiket karışıklık matrisi
        plt.subplot(3, 3, 7)
        confusion_data = []
        labels_unique = sorted(self.labels.unique())
        
        for cluster_id in range(self.kmeans_model.n_clusters):
            cluster_labels = self.results['cluster_analysis'][cluster_id]['all_labels']
            row = [cluster_labels.get(label, 0) for label in labels_unique]
            confusion_data.append(row)
        
        confusion_matrix = np.array(confusion_data)
        sns.heatmap(confusion_matrix, annot=True, fmt='d', 
                   xticklabels=labels_unique, yticklabels=[f'Küme {i}' for i in range(self.kmeans_model.n_clusters)])
        plt.title('Küme-Etiket Karışıklık Matrisi')
        plt.xlabel('Gerçek Etiketler')
        plt.ylabel('Küme ID')
        
        # 6. Metrik karşılaştırması
        plt.subplot(3, 3, 8)
        metrics = ['Silhouette', 'ARI', 'NMI']
        values = [
            self.results['clustering_metrics']['silhouette_score'],
            self.results['clustering_metrics']['adjusted_rand_index'],
            self.results['clustering_metrics']['normalized_mutual_info']
        ]
        plt.bar(metrics, values)
        plt.title('Kümeleme Metrikleri')
        plt.ylabel('Skor')
        plt.ylim(0, 1)
        
        # 7. Özet istatistikler
        plt.subplot(3, 3, 9)
        plt.text(0.1, 0.8, f"Optimal K: {self.results['optimal_k']}", transform=plt.gca().transAxes)
        plt.text(0.1, 0.7, f"Toplam Örnek: {len(self.features):,}", transform=plt.gca().transAxes)
        plt.text(0.1, 0.6, f"Özellik Sayısı: {self.results['feature_info']['n_features']}", transform=plt.gca().transAxes)
        plt.text(0.1, 0.5, f"Etiket Sayısı: {len(self.results['feature_info']['unique_labels'])}", transform=plt.gca().transAxes)
        plt.text(0.1, 0.4, f"Genel Saflık: {self.results['overall_purity']:.4f}", transform=plt.gca().transAxes)
        plt.text(0.1, 0.3, f"Silhouette: {self.results['clustering_metrics']['silhouette_score']:.4f}", transform=plt.gca().transAxes)
        plt.text(0.1, 0.2, f"ARI: {self.results['clustering_metrics']['adjusted_rand_index']:.4f}", transform=plt.gca().transAxes)
        plt.text(0.1, 0.1, f"NMI: {self.results['clustering_metrics']['normalized_mutual_info']:.4f}", transform=plt.gca().transAxes)
        plt.title('Özet İstatistikler')
        plt.axis('off')
        
        plt.tight_layout()
        plt.savefig('/Volumes/KIOXIA/tasarım_proje_cıc_ıoy/codes_3/kmeans_clustering_results.png', 
                   dpi=300, bbox_inches='tight')
        plt.show()
        
        print("Görselleştirmeler kaydedildi: kmeans_clustering_results.png")
    
    def create_detailed_report(self):
        """Detaylı analiz raporu oluştur"""
        print("\n=== DETAYLI RAPOR OLUŞTURMA ===")
        
        report = []
        report.append("CIC-IoMT-2024 K-Means Kümeleme Analizi Raporu")
        report.append("=" * 60)
        report.append(f"Analiz Tarihi: {pd.Timestamp.now()}")
        report.append("")
        
        # Veri bilgileri
        report.append("VERİ BİLGİLERİ")
        report.append("-" * 30)
        report.append(f"Toplam Örnek Sayısı: {len(self.features):,}")
        report.append(f"Özellik Sayısı: {self.results['feature_info']['n_features']}")
        report.append(f"Gerçek Etiket Sayısı: {len(self.results['feature_info']['unique_labels'])}")
        report.append("")
        
        # Etiket dağılımı
        report.append("ETİKET DAĞILIMI")
        report.append("-" * 30)
        for label, count in sorted(self.results['feature_info']['label_counts'].items()):
            percentage = (count / len(self.features)) * 100
            report.append(f"{label}: {count:,} örnek ({percentage:.2f}%)")
        report.append("")
        
        # Optimal k bulma
        report.append("OPTİMAL KÜME SAYISI")
        report.append("-" * 30)
        report.append(f"Optimal K: {self.results['optimal_k']}")
        report.append(f"Silhouette Score: {max(self.results['silhouette_scores']):.4f}")
        report.append("")
        
        # Kümeleme metrikleri
        report.append("KÜMELEME METRİKLERİ")
        report.append("-" * 30)
        metrics = self.results['clustering_metrics']
        report.append(f"Silhouette Score: {metrics['silhouette_score']:.4f}")
        report.append(f"Calinski-Harabasz Score: {metrics['calinski_harabasz_score']:.4f}")
        report.append(f"Davies-Bouldin Score: {metrics['davies_bouldin_score']:.4f}")
        report.append(f"Adjusted Rand Index: {metrics['adjusted_rand_index']:.4f}")
        report.append(f"Normalized Mutual Information: {metrics['normalized_mutual_info']:.4f}")
        report.append("")
        
        # Küme analizi
        report.append("KÜME ANALİZİ")
        report.append("-" * 30)
        for cluster_id, analysis in self.results['cluster_analysis'].items():
            report.append(f"Küme {cluster_id}:")
            report.append(f"  En baskın etiket: {analysis['dominant_label']}")
            report.append(f"  Örnek sayısı: {analysis['total_samples']}")
            report.append(f"  Saflık: {analysis['purity']:.4f}")
            report.append(f"  Etiket dağılımı: {analysis['all_labels']}")
            report.append("")
        
        # Genel değerlendirme
        report.append("GENEL DEĞERLENDİRME")
        report.append("-" * 30)
        report.append(f"Genel Saflık: {self.results['overall_purity']:.4f}")
        
        # Sonuçların yorumlanması
        if self.results['overall_purity'] > 0.7:
            purity_assessment = "Yüksek - K-Means iyi performans gösteriyor"
        elif self.results['overall_purity'] > 0.5:
            purity_assessment = "Orta - K-Means orta düzeyde performans gösteriyor"
        else:
            purity_assessment = "Düşük - K-Means düşük performans gösteriyor"
        
        report.append(f"Saflık Değerlendirmesi: {purity_assessment}")
        report.append("")
        
        # Öneriler
        report.append("ÖNERİLER")
        report.append("-" * 30)
        report.append("1. Farklı kümeleme algoritmaları (DBSCAN, Agglomerative) deneyin")
        report.append("2. Özellik seçimi veya boyut azaltma teknikleri uygulayın")
        report.append("3. Hiperparametre optimizasyonu yapın")
        report.append("4. Daha fazla veri ile model performansını test edin")
        report.append("5. Etiket kalitesini kontrol edin")
        
        # Raporu kaydet
        report_text = "\n".join(report)
        with open('/Volumes/KIOXIA/tasarım_proje_cıc_ıoy/codes_3/kmeans_clustering_report.txt', 'w', encoding='utf-8') as f:
            f.write(report_text)
        
        print("Detaylı rapor kaydedildi: kmeans_clustering_report.txt")
        return report_text
    
    def save_results_to_csv(self):
        """Sonuçları CSV dosyasına kaydet"""
        print("\n=== SONUÇLARI CSV'YE KAYDETME ===")
        
        # Sonuçları DataFrame'e çevir
        results_df = self.data.copy()
        results_df['cluster_id'] = self.cluster_labels
        results_df['predicted_label'] = [self.results['cluster_analysis'][cluster_id]['dominant_label'] 
                                       for cluster_id in self.cluster_labels]
        
        # CSV'ye kaydet
        results_df.to_csv('/Volumes/KIOXIA/tasarım_proje_cıc_ıoy/codes_3/kmeans_clustering_results.csv', 
                         index=False)
        
        print("Sonuçlar kaydedildi: kmeans_clustering_results.csv")
        
        # Küme istatistiklerini ayrı CSV'ye kaydet
        cluster_stats = []
        for cluster_id, analysis in self.results['cluster_analysis'].items():
            cluster_stats.append({
                'cluster_id': cluster_id,
                'dominant_label': analysis['dominant_label'],
                'total_samples': analysis['total_samples'],
                'purity': analysis['purity'],
                'label_distribution': str(analysis['all_labels'])
            })
        
        cluster_stats_df = pd.DataFrame(cluster_stats)
        cluster_stats_df.to_csv('/Volumes/KIOXIA/tasarım_proje_cıc_ıoy/codes_3/cluster_statistics.csv', 
                               index=False)
        
        print("Küme istatistikleri kaydedildi: cluster_statistics.csv")
    
    def run_complete_analysis(self):
        """Tam analiz sürecini çalıştır"""
        print("CIC-IoMT-2024 K-Means Kümeleme Analizi Başlatılıyor...")
        
        try:
            # 1. Veri yükleme
            self.load_and_prepare_data()
            
            # 2. Özellik hazırlama
            self.prepare_features()
            
            # 3. Optimal k bulma
            optimal_k = self.find_optimal_clusters()
            
            # 4. K-Means kümeleme
            self.perform_kmeans_clustering(optimal_k)
            
            # 5. Etiketli veri vs Kümeler karşılaştırması
            self.visualize_labeled_vs_clustered_data()
            
            # 6. Görselleştirme
            self.create_visualizations()
            
            # 7. Rapor oluşturma
            self.create_detailed_report()
            
            # 8. Sonuçları kaydetme
            self.save_results_to_csv()
            
            print("\n" + "="*60)
            print("ANALİZ TAMAMLANDI!")
            print("="*60)
            print("Oluşturulan dosyalar:")
            print("- labeled_vs_clustered_comparison.png (Etiketli vs Kümeler karşılaştırması)")
            print("- kmeans_clustering_results.png (Ana görselleştirmeler)")
            print("- kmeans_clustering_report.txt (Detaylı rapor)")
            print("- kmeans_clustering_results.csv (Sonuçlar)")
            print("- cluster_statistics.csv (Küme istatistikleri)")
            
            return self.results
            
        except Exception as e:
            print(f"Hata oluştu: {e}")
            raise

def main():
    """Ana çalıştırma fonksiyonu"""
    data_path = "/Volumes/KIOXIA/tasarım_proje_cıc_ıot"
    
    # Analyzer'ı başlat
    analyzer = KMeansAnalyzer(data_path)
    
    # Tam analizi çalıştır
    results = analyzer.run_complete_analysis()
    
    return results

if __name__ == "__main__":
    main()
