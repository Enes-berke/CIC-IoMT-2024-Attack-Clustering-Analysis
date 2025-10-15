#!/usr/bin/env python3
"""
CIC-IoMT-2024 MQTT Alt Kategorileri K-Means Kümeleme Analizi + Görselleştirme
=============================================================================

Bu script, sadece MQTT ile ilgili etiketleri içeren verileri K-Means ile analiz eder.
MQTT_DDoS, MQTT_DoS, MQTT_Malformed etiketlerinin alt kategorilerini inceler.
EK ÖZELLİK: Etiketli veriler ve kümeleme sonrası görselleştirmeler.

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
from sklearn.metrics import homogeneity_score, completeness_score, v_measure_score
from sklearn.metrics import fowlkes_mallows_score
from sklearn.manifold import TSNE
from sklearn.feature_selection import SelectKBest, f_classif, mutual_info_classif
from sklearn.model_selection import cross_val_score
from scipy import stats
from scipy.cluster.hierarchy import dendrogram, linkage
from scipy.spatial.distance import pdist
try:
    import umap
    UMAP_AVAILABLE = True
except ImportError:
    UMAP_AVAILABLE = False
    print("UMAP not available, will use PCA instead for advanced visualizations")
import warnings
from pathlib import Path
import os
from collections import Counter
import plotly.express as px
import plotly.graph_objects as go
from plotly.subplots import make_subplots
import plotly.offline as pyo

warnings.filterwarnings('ignore')

class MQTTSubcategoryAnalyzerWithVisualization:
    def __init__(self, data_path):
        self.data_path = Path(data_path)
        self.data = None
        self.features = None
        self.labels = None
        self.scaled_features = None
        self.kmeans_model = None
        self.cluster_labels = None
        self.results = {}
        
    def load_and_prepare_mqtt_data(self):
        """Sadece MQTT ile ilgili veri dosyalarını yükle ve hazırla"""
        print("=== MQTT VERİ YÜKLEME VE HAZIRLAMA ===")
        
        # Train klasöründeki CSV dosyalarını bul
        train_path = self.data_path / "CICIoMT2024" / "WiFI_and_MQTT" / "attacks" / "csv" / "train"
        csv_files = list(train_path.glob("*.csv"))
        
        # MQTT ile ilgili dosyaları filtrele
        mqtt_files = [f for f in csv_files if any(mqtt_keyword in f.name for mqtt_keyword in 
                     ['MQTT-DDoS', 'MQTT-DoS', 'MQTT-Malformed']) and not f.name.startswith('._')]
        
        print(f"Bulunan MQTT dosyaları: {len(mqtt_files)}")
        for file in mqtt_files:
            print(f"  - {file.name}")
        
        # Hedef örnek sayıları (MQTT alt kategorileri için dengeli veri seti)
        target_samples = {
            'MQTT-DDoS-Connect_Flood': 5000,
            'MQTT-DDoS-Publish_Flood': 5000,
            'MQTT-DoS-Connect_Flood': 5000,
            'MQTT-DoS-Publish_Flood': 5000,
            'MQTT-Malformed_Data': 5000
        }
        
        # Dosya isimlerinden etiketleri çıkar ve örnekle
        all_data = []
        label_mapping = {}
        
        for csv_file in mqtt_files:
            if csv_file.name.startswith('._'):
                continue
                
            try:
                print(f"Yükleniyor: {csv_file.name}")
                df = pd.read_csv(csv_file)
                
                # Dosya isminden detaylı etiket çıkar
                filename = csv_file.stem.replace('.pcap', '')
                
                # Detaylı MQTT alt kategorisi belirle
                if 'MQTT-DDoS-Connect_Flood' in filename:
                    label = 'MQTT-DDoS-Connect_Flood'
                elif 'MQTT-DDoS-Publish_Flood' in filename:
                    label = 'MQTT-DDoS-Publish_Flood'
                elif 'MQTT-DoS-Connect_Flood' in filename:
                    label = 'MQTT-DoS-Connect_Flood'
                elif 'MQTT-DoS-Publish_Flood' in filename:
                    label = 'MQTT-DoS-Publish_Flood'
                elif 'MQTT-Malformed_Data' in filename:
                    label = 'MQTT-Malformed_Data'
                else:
                    # Genel kategoriler
                    if 'MQTT-DDoS' in filename:
                        label = 'MQTT-DDoS-General'
                    elif 'MQTT-DoS' in filename:
                        label = 'MQTT-DoS-General'
                    elif 'MQTT-Malformed' in filename:
                        label = 'MQTT-Malformed-General'
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
            raise ValueError("Hiç MQTT verisi yüklenemedi!")
        
        # Tüm verileri birleştir
        self.data = pd.concat(all_data, ignore_index=True)
        print(f"\nToplam MQTT verisi: {len(self.data)} örnek")
        
        # Etiket dağılımını göster
        print("\nMQTT Alt Kategori Dağılımı:")
        for label, count in sorted(label_mapping.items()):
            percentage = (count / len(self.data)) * 100
            print(f"  - {label}: {count:,} örnek ({percentage:.1f}%)")
        
        self.results['label_distribution'] = label_mapping
        self.results['target_samples'] = target_samples
        return self.data
    
    def prepare_features(self):
        """Özellik matrisini hazırla (PCA kullanmadan)"""
        print("\n=== MQTT ÖZELLİK HAZIRLAMA ===")
        
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
        
        print(f"MQTT Alt kategori sayısı: {len(unique_labels)}")
        print(f"Alt kategoriler: {unique_labels}")
        
        self.results['feature_info'] = {
            'n_features': len(feature_columns),
            'n_samples': len(self.features),
            'unique_labels': unique_labels,
            'label_counts': dict(Counter(self.labels))
        }
        
        return self.scaled_features, self.numeric_labels
    
    def visualize_labeled_data(self):
        """Etiketli verileri görselleştir (kümeleme öncesi)"""
        print("\n=== ETİKETLİ VERİ GÖRSELLEŞTİRME ===")
        
        # PCA ile boyut azaltma
        pca = PCA(n_components=2, random_state=42)
        pca_result = pca.fit_transform(self.scaled_features)
        
        # PCA 3D için
        pca_3d = PCA(n_components=3, random_state=42)
        pca_3d_result = pca_3d.fit_transform(self.scaled_features)
        
        # Görselleştirme - 2x3 layout
        fig, axes = plt.subplots(2, 3, figsize=(20, 12))
        
        # 1. PCA - 2D (daha net)
        scatter = axes[0, 0].scatter(pca_result[:, 0], pca_result[:, 1], 
                                   c=self.numeric_labels, cmap='tab10', alpha=0.8, s=20)
        axes[0, 0].set_title('MQTT Etiketli Veriler - PCA (2D)', fontsize=14, fontweight='bold')
        axes[0, 0].set_xlabel(f'PC1 ({pca.explained_variance_ratio_[0]:.2%})')
        axes[0, 0].set_ylabel(f'PC2 ({pca.explained_variance_ratio_[1]:.2%})')
        axes[0, 0].grid(True, alpha=0.3)
        
        # Legend ekle
        unique_labels = sorted(self.labels.unique())
        legend_elements = [plt.Line2D([0], [0], marker='o', color='w', 
                                    markerfacecolor=plt.cm.tab10(i/len(unique_labels)), 
                                    markersize=10, label=label.replace('MQTT-', ''))
                         for i, label in enumerate(unique_labels)]
        axes[0, 0].legend(handles=legend_elements, bbox_to_anchor=(1.05, 1), loc='upper left')
        
        # 2. Özellik Korelasyon Matrisi (daha açıklayıcı)
        # En önemli 10 özelliği seç
        feature_importance = np.abs(pca.components_).mean(axis=0)
        top_features_idx = np.argsort(feature_importance)[-10:]
        top_features_data = self.features.iloc[:, top_features_idx]
        
        correlation_matrix = top_features_data.corr()
        im = axes[0, 1].imshow(correlation_matrix, cmap='RdBu_r', vmin=-1, vmax=1)
        axes[0, 1].set_title('En Önemli 10 Özellik Korelasyon Matrisi', fontsize=14, fontweight='bold')
        axes[0, 1].set_xticks(range(len(top_features_idx)))
        axes[0, 1].set_yticks(range(len(top_features_idx)))
        axes[0, 1].set_xticklabels([self.features.columns[i][:15] + '...' if len(self.features.columns[i]) > 15 
                                   else self.features.columns[i] for i in top_features_idx], rotation=45)
        axes[0, 1].set_yticklabels([self.features.columns[i][:15] + '...' if len(self.features.columns[i]) > 15 
                                   else self.features.columns[i] for i in top_features_idx])
        
        # Colorbar ekle
        plt.colorbar(im, ax=axes[0, 1], shrink=0.8)
        
        # 3. Etiket dağılımı - Pasta grafik (daha net)
        label_counts = Counter(self.labels)
        colors = ['#ff9999', '#66b3ff', '#99ff99', '#ffcc99', '#ff99cc']
        wedges, texts, autotexts = axes[0, 2].pie(label_counts.values(), 
                                                 labels=[label.replace('MQTT-', '') for label in label_counts.keys()],
                                                 colors=colors[:len(label_counts)],
                                                 autopct='%1.1f%%', startangle=90)
        axes[0, 2].set_title('MQTT Alt Kategori Dağılımı', fontsize=14, fontweight='bold')
        
        # 4. Etiket dağılımı - Bar grafik (sayılarla)
        bars = axes[1, 0].bar(range(len(label_counts)), label_counts.values(), 
                             color=colors[:len(label_counts)], alpha=0.8)
        axes[1, 0].set_title('MQTT Alt Kategori Sayıları', fontsize=14, fontweight='bold')
        axes[1, 0].set_xlabel('MQTT Alt Kategoriler')
        axes[1, 0].set_ylabel('Örnek Sayısı')
        axes[1, 0].set_xticks(range(len(label_counts)))
        axes[1, 0].set_xticklabels([label.replace('MQTT-', '') for label in label_counts.keys()], 
                                  rotation=45)
        axes[1, 0].grid(True, alpha=0.3)
        
        # Bar üzerine sayıları ekle
        for i, bar in enumerate(bars):
            height = bar.get_height()
            axes[1, 0].text(bar.get_x() + bar.get_width()/2., height + height*0.01,
                           f'{int(height):,}', ha='center', va='bottom', fontweight='bold')
        
        # 5. Özellik Önemlilik (PCA bileşenlerine göre)
        feature_names = [col[:20] + '...' if len(col) > 20 else col for col in self.features.columns]
        importance_scores = np.abs(pca.components_[0])  # İlk bileşen
        top_15_idx = np.argsort(importance_scores)[-15:]
        
        y_pos = np.arange(len(top_15_idx))
        bars = axes[1, 1].barh(y_pos, importance_scores[top_15_idx], color='lightblue', alpha=0.8)
        axes[1, 1].set_yticks(y_pos)
        axes[1, 1].set_yticklabels([feature_names[i] for i in top_15_idx])
        axes[1, 1].set_xlabel('Özellik Önemlilik (PC1)')
        axes[1, 1].set_title('En Önemli 15 Özellik (PC1)', fontsize=14, fontweight='bold')
        axes[1, 1].grid(True, alpha=0.3)
        
        # 6. Veri Özeti (daha detaylı)
        axes[1, 2].text(0.1, 0.9, "MQTT VERİ ÖZETİ", transform=axes[1, 2].transAxes, 
                       fontsize=16, fontweight='bold')
        axes[1, 2].text(0.1, 0.8, f"Toplam Örnek: {len(self.features):,}", 
                       transform=axes[1, 2].transAxes, fontsize=12)
        axes[1, 2].text(0.1, 0.75, f"Özellik Sayısı: {len(self.features.columns)}", 
                       transform=axes[1, 2].transAxes, fontsize=12)
        axes[1, 2].text(0.1, 0.7, f"MQTT Alt Kategori: {len(unique_labels)}", 
                       transform=axes[1, 2].transAxes, fontsize=12)
        axes[1, 2].text(0.1, 0.65, f"PCA PC1 Açıklanan Varyans: {pca.explained_variance_ratio_[0]:.2%}", 
                       transform=axes[1, 2].transAxes, fontsize=12)
        axes[1, 2].text(0.1, 0.6, f"PCA PC2 Açıklanan Varyans: {pca.explained_variance_ratio_[1]:.2%}", 
                       transform=axes[1, 2].transAxes, fontsize=12)
        axes[1, 2].text(0.1, 0.55, f"Toplam Açıklanan Varyans: {pca.explained_variance_ratio_.sum():.2%}", 
                       transform=axes[1, 2].transAxes, fontsize=12)
        
        axes[1, 2].text(0.1, 0.45, "MQTT Alt Kategoriler:", transform=axes[1, 2].transAxes, 
                       fontsize=12, fontweight='bold')
        
        for i, label in enumerate(unique_labels):
            axes[1, 2].text(0.1, 0.4 - i*0.04, f"• {label.replace('MQTT-', '')} ({label_counts[label]:,})", 
                           transform=axes[1, 2].transAxes, fontsize=10)
        
        axes[1, 2].set_title('Detaylı Veri Bilgileri', fontsize=14, fontweight='bold')
        axes[1, 2].axis('off')
        
        plt.tight_layout()
        plt.savefig('/Volumes/KIOXIA/tasarım_proje_cıc_ıot/codes_5/mqtt_labeled_data_visualization.png', 
                   dpi=300, bbox_inches='tight')
        plt.show()
        
        print("Etiketli veri görselleştirmesi kaydedildi: mqtt_labeled_data_visualization.png")
        
        # Sonuçları sakla
        self.pca_result = pca_result
        self.pca_3d_result = pca_3d_result
        self.pca = pca
        self.pca_3d = pca_3d
    
    def visualize_clustering_results(self):
        """Kümeleme sonuçlarını görselleştir"""
        print("\n=== KÜMELEME SONUÇLARI GÖRSELLEŞTİRME ===")
        
        # Görselleştirme - 2x3 layout (daha net ve açıklayıcı)
        fig, axes = plt.subplots(2, 3, figsize=(20, 12))
        
        # 1. PCA - Gerçek etiketler vs K-Means kümeleri karşılaştırması
        scatter1 = axes[0, 0].scatter(self.pca_result[:, 0], self.pca_result[:, 1], 
                                    c=self.numeric_labels, cmap='tab10', alpha=0.8, s=15)
        axes[0, 0].set_title('Gerçek MQTT Etiketleri - PCA', fontsize=14, fontweight='bold')
        axes[0, 0].set_xlabel(f'PC1 ({self.pca.explained_variance_ratio_[0]:.2%})')
        axes[0, 0].set_ylabel(f'PC2 ({self.pca.explained_variance_ratio_[1]:.2%})')
        axes[0, 0].grid(True, alpha=0.3)
        
        # 2. PCA - K-Means kümeleri
        scatter2 = axes[0, 1].scatter(self.pca_result[:, 0], self.pca_result[:, 1], 
                                    c=self.cluster_labels, cmap='tab10', alpha=0.8, s=15)
        axes[0, 1].set_title('K-Means Kümeleri - PCA', fontsize=14, fontweight='bold')
        axes[0, 1].set_xlabel(f'PC1 ({self.pca.explained_variance_ratio_[0]:.2%})')
        axes[0, 1].set_ylabel(f'PC2 ({self.pca.explained_variance_ratio_[1]:.2%})')
        axes[0, 1].grid(True, alpha=0.3)
        
        # 3. Karışıklık Matrisi (Küme vs Etiket)
        confusion_data = []
        labels_unique = sorted(self.labels.unique())
        
        for cluster_id in range(self.kmeans_model.n_clusters):
            cluster_labels = self.results['cluster_analysis'][cluster_id]['all_labels']
            row = [cluster_labels.get(label, 0) for label in labels_unique]
            confusion_data.append(row)
        
        confusion_matrix = np.array(confusion_data)
        im = axes[0, 2].imshow(confusion_matrix, cmap='Blues', aspect='auto')
        axes[0, 2].set_title('Küme-Etiket Karışıklık Matrisi', fontsize=14, fontweight='bold')
        axes[0, 2].set_xlabel('Gerçek Etiketler')
        axes[0, 2].set_ylabel('Küme ID')
        axes[0, 2].set_xticks(range(len(labels_unique)))
        axes[0, 2].set_xticklabels([label.replace('MQTT-', '') for label in labels_unique], rotation=45)
        axes[0, 2].set_yticks(range(self.kmeans_model.n_clusters))
        axes[0, 2].set_yticklabels([f'Küme {i}' for i in range(self.kmeans_model.n_clusters)])
        
        # Matris üzerine sayıları ekle
        for i in range(self.kmeans_model.n_clusters):
            for j in range(len(labels_unique)):
                text = axes[0, 2].text(j, i, confusion_matrix[i, j], 
                                     ha="center", va="center", color="black", fontweight='bold')
        
        # 4. Küme Dağılımı (Bar + Pasta)
        cluster_counts = Counter(self.cluster_labels)
        bars = axes[1, 0].bar(cluster_counts.keys(), cluster_counts.values(), 
                             color='skyblue', alpha=0.8, edgecolor='black', linewidth=1)
        axes[1, 0].set_title('Küme Dağılımı', fontsize=14, fontweight='bold')
        axes[1, 0].set_xlabel('Küme ID')
        axes[1, 0].set_ylabel('Örnek Sayısı')
        axes[1, 0].grid(True, alpha=0.3)
        
        # Bar üzerine sayıları ekle
        for bar in bars:
            height = bar.get_height()
            axes[1, 0].text(bar.get_x() + bar.get_width()/2., height + height*0.01,
                           f'{int(height):,}', ha='center', va='bottom', fontweight='bold')
        
        # 5. Küme Saflığı (detaylı)
        cluster_purities = [self.results['cluster_analysis'][i]['purity'] 
                          for i in range(self.kmeans_model.n_clusters)]
        cluster_sizes = [self.results['cluster_analysis'][i]['total_samples'] 
                        for i in range(self.kmeans_model.n_clusters)]
        
        # Bubble chart: X=Küme ID, Y=Saflık, Size=Küme boyutu
        scatter = axes[1, 1].scatter(range(len(cluster_purities)), cluster_purities, 
                                   s=[size/50 for size in cluster_sizes], 
                                   c=cluster_purities, cmap='RdYlGn', alpha=0.7, 
                                   edgecolors='black', linewidth=1)
        axes[1, 1].set_title('Küme Saflığı (Boyut=Küme Büyüklüğü)', fontsize=14, fontweight='bold')
        axes[1, 1].set_xlabel('Küme ID')
        axes[1, 1].set_ylabel('Saflık')
        axes[1, 1].set_ylim(0, 1.05)
        axes[1, 1].grid(True, alpha=0.3)
        
        # Bubble üzerine değerleri ekle
        for i, (purity, size) in enumerate(zip(cluster_purities, cluster_sizes)):
            axes[1, 1].text(i, purity + 0.02, f'{purity:.3f}\n({size:,})', 
                           ha='center', va='bottom', fontweight='bold', fontsize=9)
        
        # Colorbar ekle
        cbar = plt.colorbar(scatter, ax=axes[1, 1])
        cbar.set_label('Saflık', rotation=270, labelpad=20)
        
        # 6. Performans Metrikleri ve Özet
        axes[1, 2].text(0.1, 0.9, "KÜMELEME PERFORMANSI", transform=axes[1, 2].transAxes, 
                       fontsize=16, fontweight='bold')
        
        metrics = self.results['clustering_metrics']
        axes[1, 2].text(0.1, 0.8, f"Silhouette Score: {metrics['silhouette_score']:.4f}", 
                       transform=axes[1, 2].transAxes, fontsize=12)
        axes[1, 2].text(0.1, 0.75, f"Adjusted Rand Index: {metrics['adjusted_rand_index']:.4f}", 
                       transform=axes[1, 2].transAxes, fontsize=12)
        axes[1, 2].text(0.1, 0.7, f"Normalized Mutual Info: {metrics['normalized_mutual_info']:.4f}", 
                       transform=axes[1, 2].transAxes, fontsize=12)
        axes[1, 2].text(0.1, 0.65, f"Genel Saflık: {self.results['overall_purity']:.4f}", 
                       transform=axes[1, 2].transAxes, fontsize=12)
        
        axes[1, 2].text(0.1, 0.55, f"Optimal K: {self.results['optimal_k']}", 
                       transform=axes[1, 2].transAxes, fontsize=12)
        axes[1, 2].text(0.1, 0.5, f"Toplam Örnek: {len(self.features):,}", 
                       transform=axes[1, 2].transAxes, fontsize=12)
        
        # En iyi kümeler
        axes[1, 2].text(0.1, 0.4, "En İyi Kümeler:", transform=axes[1, 2].transAxes, 
                       fontsize=12, fontweight='bold')
        
        # Saflığa göre sırala
        sorted_clusters = sorted(enumerate(cluster_purities), key=lambda x: x[1], reverse=True)[:3]
        for i, (cluster_id, purity) in enumerate(sorted_clusters):
            dominant_label = self.results['cluster_analysis'][cluster_id]['dominant_label']
            axes[1, 2].text(0.1, 0.35 - i*0.05, 
                           f"Küme {cluster_id}: {purity:.3f} ({dominant_label.replace('MQTT-', '')})", 
                           transform=axes[1, 2].transAxes, fontsize=10)
        
        axes[1, 2].set_title('Detaylı Performans Analizi', fontsize=14, fontweight='bold')
        axes[1, 2].axis('off')
        
        plt.tight_layout()
        plt.savefig('/Volumes/KIOXIA/tasarım_proje_cıc_ıot/codes_5/mqtt_clustering_results_visualization.png', 
                   dpi=300, bbox_inches='tight')
        plt.show()
        
        print("Kümeleme sonuçları görselleştirmesi kaydedildi: mqtt_clustering_results_visualization.png")
    
    def find_optimal_clusters(self):
        """Optimal küme sayısını bul"""
        print("\n=== MQTT OPTİMAL KÜME SAYISI BULMA ===")
        
        # Elbow method ve silhouette score kullanarak optimal k'yı bul
        max_clusters = min(15, len(np.unique(self.numeric_labels)) + 3)
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
        print("\n=== MQTT K-MEANS KÜMELEME ===")
        
        if n_clusters is None:
            n_clusters = self.results['optimal_k']
        
        # K-Means modelini eğit
        self.kmeans_model = KMeans(n_clusters=n_clusters, random_state=42, n_init=10)
        self.cluster_labels = self.kmeans_model.fit_predict(self.scaled_features)
        
        print(f"MQTT K-Means kümeleme tamamlandı (k={n_clusters})")
        
        # Küme istatistikleri
        cluster_counts = Counter(self.cluster_labels)
        print("\nMQTT Küme Dağılımı:")
        for cluster_id, count in sorted(cluster_counts.items()):
            print(f"  Küme {cluster_id}: {count} örnek")
        
        # Gerçek etiketlerle karşılaştır
        self.evaluate_clustering()
        
        return self.cluster_labels
    
    def evaluate_clustering(self):
        """Kümeleme sonuçlarını değerlendir"""
        print("\n=== MQTT KÜMELEME DEĞERLENDİRME ===")
        
        # Temel kümeleme metrikleri
        silhouette_avg = silhouette_score(self.scaled_features, self.cluster_labels)
        calinski_score = calinski_harabasz_score(self.scaled_features, self.cluster_labels)
        davies_bouldin = davies_bouldin_score(self.scaled_features, self.cluster_labels)
        
        print(f"Silhouette Score: {silhouette_avg:.4f}")
        print(f"Calinski-Harabasz Score: {calinski_score:.4f}")
        print(f"Davies-Bouldin Score: {davies_bouldin:.4f}")
        
        # Gerçek etiketlerle karşılaştırma metrikleri
        ari_score = adjusted_rand_score(self.numeric_labels, self.cluster_labels)
        nmi_score = normalized_mutual_info_score(self.numeric_labels, self.cluster_labels)
        
        # Ek metrikler
        homogeneity = homogeneity_score(self.numeric_labels, self.cluster_labels)
        completeness = completeness_score(self.numeric_labels, self.cluster_labels)
        v_measure = v_measure_score(self.numeric_labels, self.cluster_labels)
        fowlkes_mallows = fowlkes_mallows_score(self.numeric_labels, self.cluster_labels)
        
        print(f"Adjusted Rand Index: {ari_score:.4f}")
        print(f"Normalized Mutual Information: {nmi_score:.4f}")
        print(f"Homogeneity Score: {homogeneity:.4f}")
        print(f"Completeness Score: {completeness:.4f}")
        print(f"V-Measure Score: {v_measure:.4f}")
        print(f"Fowlkes-Mallows Index: {fowlkes_mallows:.4f}")
        
        # İstatistiksel anlamlılık testi
        self.perform_statistical_tests()
        
        self.results['clustering_metrics'] = {
            'silhouette_score': silhouette_avg,
            'calinski_harabasz_score': calinski_score,
            'davies_bouldin_score': davies_bouldin,
            'adjusted_rand_index': ari_score,
            'normalized_mutual_info': nmi_score,
            'homogeneity_score': homogeneity,
            'completeness_score': completeness,
            'v_measure_score': v_measure,
            'fowlkes_mallows_index': fowlkes_mallows
        }
        
        # Küme-etiket karışıklık matrisi oluştur
        self.create_confusion_analysis()
    
    def create_confusion_analysis(self):
        """Küme ve etiket karışıklık analizi"""
        print("\n=== MQTT KÜME-ETİKET ANALİZİ ===")
        
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
        print(f"\nMQTT Genel Saflık: {overall_purity:.4f}")
        
        self.results['overall_purity'] = overall_purity
    
    def perform_statistical_tests(self):
        """İstatistiksel anlamlılık testleri yap"""
        print("\n=== MQTT İSTATİSTİKSEL TESTLER ===")
        
        # Küme içi ve küme arası varyans analizi
        cluster_centers = self.kmeans_model.cluster_centers_
        within_cluster_ss = 0
        between_cluster_ss = 0
        
        # Genel merkez
        overall_center = np.mean(self.scaled_features, axis=0)
        
        for i in range(self.kmeans_model.n_clusters):
            cluster_mask = self.cluster_labels == i
            cluster_data = self.scaled_features[cluster_mask]
            
            if len(cluster_data) > 0:
                # Küme içi kareler toplamı
                within_cluster_ss += np.sum((cluster_data - cluster_centers[i])**2)
                
                # Küme arası kareler toplamı
                between_cluster_ss += len(cluster_data) * np.sum((cluster_centers[i] - overall_center)**2)
        
        # F-istatistiği
        n_samples = len(self.scaled_features)
        n_clusters = self.kmeans_model.n_clusters
        df_between = n_clusters - 1
        df_within = n_samples - n_clusters
        
        if df_within > 0 and within_cluster_ss > 0:
            f_statistic = (between_cluster_ss / df_between) / (within_cluster_ss / df_within)
            
            # P-değeri hesapla (yaklaşık)
            p_value = 1 - stats.f.cdf(f_statistic, df_between, df_within)
            
            print(f"F-istatistiği: {f_statistic:.4f}")
            print(f"P-değeri: {p_value:.6f}")
            print(f"İstatistiksel anlamlılık: {'Evet' if p_value < 0.05 else 'Hayır'} (α=0.05)")
            
            self.results['statistical_tests'] = {
                'f_statistic': f_statistic,
                'p_value': p_value,
                'significant': p_value < 0.05,
                'within_cluster_ss': within_cluster_ss,
                'between_cluster_ss': between_cluster_ss
            }
        
        # Küme kararlılık analizi
        self.analyze_cluster_stability()
    
    def analyze_cluster_stability(self):
        """Küme kararlılık analizi yap"""
        print("\n=== MQTT KÜME KARARLILIK ANALİZİ ===")
        
        # Bootstrap ile kararlılık testi
        n_bootstrap = 10
        stability_scores = []
        
        for i in range(n_bootstrap):
            # Bootstrap örneği
            bootstrap_indices = np.random.choice(len(self.scaled_features), 
                                               size=len(self.scaled_features), 
                                               replace=True)
            bootstrap_data = self.scaled_features[bootstrap_indices]
            
            # K-Means uygula
            kmeans_bootstrap = KMeans(n_clusters=self.kmeans_model.n_clusters, 
                                    random_state=42+i, n_init=5)
            bootstrap_labels = kmeans_bootstrap.fit_predict(bootstrap_data)
            
            # Orijinal kümelerle karşılaştır
            bootstrap_ari = adjusted_rand_score(self.cluster_labels[bootstrap_indices], 
                                              bootstrap_labels)
            stability_scores.append(bootstrap_ari)
        
        mean_stability = np.mean(stability_scores)
        std_stability = np.std(stability_scores)
        
        print(f"Ortalama kararlılık skoru: {mean_stability:.4f} ± {std_stability:.4f}")
        
        if 'statistical_tests' not in self.results:
            self.results['statistical_tests'] = {}
        
        self.results['statistical_tests']['cluster_stability'] = {
            'mean_stability': mean_stability,
            'std_stability': std_stability,
            'stability_scores': stability_scores
        }
    
    def analyze_feature_importance(self):
        """Özellik önemlilik analizi yap"""
        print("\n=== MQTT ÖZELLİK ÖNEMLİLİK ANALİZİ ===")
        
        # F-test ile özellik seçimi
        f_scores, f_pvalues = f_classif(self.scaled_features, self.numeric_labels)
        
        # Mutual information ile özellik seçimi
        mi_scores = mutual_info_classif(self.scaled_features, self.numeric_labels, random_state=42)
        
        # En önemli 20 özelliği seç
        top_features_f = np.argsort(f_scores)[-20:][::-1]
        top_features_mi = np.argsort(mi_scores)[-20:][::-1]
        
        print("En önemli 10 özellik (F-test):")
        for i, idx in enumerate(top_features_f[:10]):
            print(f"  {i+1}. {self.features.columns[idx]}: F={f_scores[idx]:.4f}, p={f_pvalues[idx]:.6f}")
        
        print("\nEn önemli 10 özellik (Mutual Information):")
        for i, idx in enumerate(top_features_mi[:10]):
            print(f"  {i+1}. {self.features.columns[idx]}: MI={mi_scores[idx]:.4f}")
        
        # Özellik önemlilik sonuçlarını sakla
        self.results['feature_importance'] = {
            'f_scores': f_scores,
            'f_pvalues': f_pvalues,
            'mi_scores': mi_scores,
            'top_features_f': top_features_f,
            'top_features_mi': top_features_mi,
            'feature_names': list(self.features.columns)
        }
        
        return top_features_f, top_features_mi
    
    def create_visualizations(self):
        """Görselleştirmeler oluştur"""
        print("\n=== MQTT GÖRSELLEŞTİRME OLUŞTURMA ===")
        
        # Matplotlib stilini ayarla
        plt.style.use('seaborn-v0_8')
        fig = plt.figure(figsize=(20, 16))
        
        # 1. Optimal k bulma grafikleri
        plt.subplot(3, 3, 1)
        plt.plot(self.results['k_range'], self.results['inertias'], 'bo-')
        plt.xlabel('Küme Sayısı (k)')
        plt.ylabel('Inertia')
        plt.title('MQTT Elbow Method - Optimal K Bulma')
        plt.grid(True)
        
        plt.subplot(3, 3, 2)
        plt.plot(self.results['k_range'], self.results['silhouette_scores'], 'ro-')
        plt.xlabel('Küme Sayısı (k)')
        plt.ylabel('Silhouette Score')
        plt.title('MQTT Silhouette Score - Optimal K Bulma')
        plt.grid(True)
        
        plt.subplot(3, 3, 3)
        plt.plot(self.results['k_range'], self.results['calinski_scores'], 'go-')
        plt.xlabel('Küme Sayısı (k)')
        plt.ylabel('Calinski-Harabasz Score')
        plt.title('MQTT Calinski-Harabasz Score')
        plt.grid(True)
        
        # 2. Küme dağılımı
        plt.subplot(3, 3, 4)
        cluster_counts = Counter(self.cluster_labels)
        plt.bar(cluster_counts.keys(), cluster_counts.values(), color='skyblue')
        plt.xlabel('Küme ID')
        plt.ylabel('Örnek Sayısı')
        plt.title('MQTT Küme Dağılımı')
        
        # 3. Etiket dağılımı
        plt.subplot(3, 3, 5)
        label_counts = Counter(self.labels)
        colors = ['lightcoral', 'lightblue', 'lightgreen', 'lightyellow', 'lightpink']
        plt.bar(range(len(label_counts)), label_counts.values(), color=colors[:len(label_counts)])
        plt.xlabel('MQTT Alt Kategoriler')
        plt.ylabel('Örnek Sayısı')
        plt.title('MQTT Alt Kategori Dağılımı')
        plt.xticks(range(len(label_counts)), [label.replace('MQTT-', '') for label in label_counts.keys()], rotation=45)
        
        # 4. Küme saflığı
        plt.subplot(3, 3, 6)
        cluster_purities = [self.results['cluster_analysis'][i]['purity'] 
                          for i in range(self.kmeans_model.n_clusters)]
        plt.bar(range(len(cluster_purities)), cluster_purities, color='lightgreen')
        plt.xlabel('Küme ID')
        plt.ylabel('Saflık')
        plt.title('MQTT Küme Saflığı')
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
                   xticklabels=[label.replace('MQTT-', '') for label in labels_unique], 
                   yticklabels=[f'Küme {i}' for i in range(self.kmeans_model.n_clusters)],
                   cmap='Blues')
        plt.title('MQTT Küme-Etiket Karışıklık Matrisi')
        plt.xlabel('MQTT Alt Kategoriler')
        plt.ylabel('Küme ID')
        
        # 6. Metrik karşılaştırması
        plt.subplot(3, 3, 8)
        metrics = ['Silhouette', 'ARI', 'NMI']
        values = [
            self.results['clustering_metrics']['silhouette_score'],
            self.results['clustering_metrics']['adjusted_rand_index'],
            self.results['clustering_metrics']['normalized_mutual_info']
        ]
        plt.bar(metrics, values, color=['orange', 'purple', 'brown'])
        plt.title('MQTT Kümeleme Metrikleri')
        plt.ylabel('Skor')
        plt.ylim(0, 1)
        
        # 7. Özet istatistikler
        plt.subplot(3, 3, 9)
        plt.text(0.1, 0.8, f"Optimal K: {self.results['optimal_k']}", transform=plt.gca().transAxes)
        plt.text(0.1, 0.7, f"Toplam Örnek: {len(self.features):,}", transform=plt.gca().transAxes)
        plt.text(0.1, 0.6, f"Özellik Sayısı: {self.results['feature_info']['n_features']}", transform=plt.gca().transAxes)
        plt.text(0.1, 0.5, f"MQTT Alt Kategori: {len(self.results['feature_info']['unique_labels'])}", transform=plt.gca().transAxes)
        plt.text(0.1, 0.4, f"Genel Saflık: {self.results['overall_purity']:.4f}", transform=plt.gca().transAxes)
        plt.text(0.1, 0.3, f"Silhouette: {self.results['clustering_metrics']['silhouette_score']:.4f}", transform=plt.gca().transAxes)
        plt.text(0.1, 0.2, f"ARI: {self.results['clustering_metrics']['adjusted_rand_index']:.4f}", transform=plt.gca().transAxes)
        plt.text(0.1, 0.1, f"NMI: {self.results['clustering_metrics']['normalized_mutual_info']:.4f}", transform=plt.gca().transAxes)
        plt.title('MQTT Özet İstatistikler')
        plt.axis('off')
        
        plt.tight_layout()
        plt.savefig('/Volumes/KIOXIA/tasarım_proje_cıc_ıot/codes_5/mqtt_clustering_results.png', 
                   dpi=300, bbox_inches='tight')
        plt.show()
        
        print("MQTT görselleştirmeler kaydedildi: mqtt_clustering_results.png")
    
    def create_advanced_visualizations(self):
        """Gelişmiş görselleştirmeler oluştur (t-SNE, UMAP, dendrogram)"""
        print("\n=== MQTT GELİŞMİŞ GÖRSELLEŞTİRME ===")
        
        # t-SNE görselleştirmesi
        print("t-SNE görselleştirmesi oluşturuluyor...")
        tsne = TSNE(n_components=2, random_state=42, perplexity=30, n_iter=1000)
        tsne_result = tsne.fit_transform(self.scaled_features)
        
        # UMAP görselleştirmesi
        if UMAP_AVAILABLE:
            print("UMAP görselleştirmesi oluşturuluyor...")
            try:
                reducer = umap.UMAP(n_components=2, random_state=42, n_neighbors=15, min_dist=0.1)
                umap_result = reducer.fit_transform(self.scaled_features)
            except:
                print("UMAP hatası, PCA kullanılıyor...")
                umap_result = self.pca_result
        else:
            print("UMAP mevcut değil, PCA kullanılıyor...")
            umap_result = self.pca_result
        
        # Hierarchical clustering dendrogram
        print("Hierarchical clustering dendrogram oluşturuluyor...")
        # Örnek sayısını sınırla (dendrogram için)
        sample_size = min(1000, len(self.scaled_features))
        sample_indices = np.random.choice(len(self.scaled_features), sample_size, replace=False)
        sample_data = self.scaled_features[sample_indices]
        
        # Distance matrix hesapla
        distances = pdist(sample_data, metric='euclidean')
        linkage_matrix = linkage(distances, method='ward')
        
        # Görselleştirme - 2x3 layout
        fig, axes = plt.subplots(2, 3, figsize=(20, 12))
        
        # 1. t-SNE - Gerçek etiketler
        scatter1 = axes[0, 0].scatter(tsne_result[:, 0], tsne_result[:, 1], 
                                    c=self.numeric_labels, cmap='tab10', alpha=0.7, s=20)
        axes[0, 0].set_title('t-SNE - Gerçek MQTT Etiketleri', fontsize=14, fontweight='bold')
        axes[0, 0].set_xlabel('t-SNE 1')
        axes[0, 0].set_ylabel('t-SNE 2')
        axes[0, 0].grid(True, alpha=0.3)
        
        # 2. t-SNE - K-Means kümeleri
        scatter2 = axes[0, 1].scatter(tsne_result[:, 0], tsne_result[:, 1], 
                                    c=self.cluster_labels, cmap='tab10', alpha=0.7, s=20)
        axes[0, 1].set_title('t-SNE - K-Means Kümeleri', fontsize=14, fontweight='bold')
        axes[0, 1].set_xlabel('t-SNE 1')
        axes[0, 1].set_ylabel('t-SNE 2')
        axes[0, 1].grid(True, alpha=0.3)
        
        # 3. UMAP - Gerçek etiketler
        scatter3 = axes[0, 2].scatter(umap_result[:, 0], umap_result[:, 1], 
                                    c=self.numeric_labels, cmap='tab10', alpha=0.7, s=20)
        axes[0, 2].set_title('UMAP - Gerçek MQTT Etiketleri', fontsize=14, fontweight='bold')
        axes[0, 2].set_xlabel('UMAP 1')
        axes[0, 2].set_ylabel('UMAP 2')
        axes[0, 2].grid(True, alpha=0.3)
        
        # 4. UMAP - K-Means kümeleri
        scatter4 = axes[1, 0].scatter(umap_result[:, 0], umap_result[:, 1], 
                                    c=self.cluster_labels, cmap='tab10', alpha=0.7, s=20)
        axes[1, 0].set_title('UMAP - K-Means Kümeleri', fontsize=14, fontweight='bold')
        axes[1, 0].set_xlabel('UMAP 1')
        axes[1, 0].set_ylabel('UMAP 2')
        axes[1, 0].grid(True, alpha=0.3)
        
        # 5. Dendrogram
        dendrogram(linkage_matrix, ax=axes[1, 1], leaf_rotation=90, leaf_font_size=8)
        axes[1, 1].set_title('Hierarchical Clustering Dendrogram', fontsize=14, fontweight='bold')
        axes[1, 1].set_xlabel('Örnek İndeksi')
        axes[1, 1].set_ylabel('Mesafe')
        
        # 6. Özellik önemlilik (eğer analiz yapıldıysa)
        if 'feature_importance' in self.results:
            top_features = self.results['feature_importance']['top_features_f'][:15]
            feature_names = [self.results['feature_importance']['feature_names'][i][:20] + '...' 
                           if len(self.results['feature_importance']['feature_names'][i]) > 20
                           else self.results['feature_importance']['feature_names'][i] 
                           for i in top_features]
            f_scores = self.results['feature_importance']['f_scores'][top_features]
            
            y_pos = np.arange(len(feature_names))
            bars = axes[1, 2].barh(y_pos, f_scores, color='lightcoral', alpha=0.8)
            axes[1, 2].set_yticks(y_pos)
            axes[1, 2].set_yticklabels(feature_names)
            axes[1, 2].set_xlabel('F-Score')
            axes[1, 2].set_title('En Önemli 15 Özellik (F-Test)', fontsize=14, fontweight='bold')
            axes[1, 2].grid(True, alpha=0.3)
        else:
            axes[1, 2].text(0.5, 0.5, 'Özellik önemlilik analizi\nhenüz yapılmadı', 
                           ha='center', va='center', transform=axes[1, 2].transAxes, fontsize=12)
            axes[1, 2].set_title('Özellik Önemlilik', fontsize=14, fontweight='bold')
        
        plt.tight_layout()
        plt.savefig('/Volumes/KIOXIA/tasarım_proje_cıc_ıot/codes_5/mqtt_advanced_visualizations.png', 
                   dpi=300, bbox_inches='tight')
        plt.show()
        
        print("Gelişmiş görselleştirmeler kaydedildi: mqtt_advanced_visualizations.png")
        
        # Sonuçları sakla
        self.tsne_result = tsne_result
        self.umap_result = umap_result
    
    def create_detailed_report(self):
        """Detaylı analiz raporu oluştur"""
        print("\n=== MQTT DETAYLI RAPOR OLUŞTURMA ===")
        
        report = []
        report.append("CIC-IoMT-2024 MQTT Alt Kategorileri K-Means Kümeleme Analizi Raporu")
        report.append("=" * 80)
        report.append(f"Analiz Tarihi: {pd.Timestamp.now()}")
        report.append("")
        
        # Veri bilgileri
        report.append("MQTT VERİ BİLGİLERİ")
        report.append("-" * 40)
        report.append(f"Toplam Örnek Sayısı: {len(self.features):,}")
        report.append(f"Özellik Sayısı: {self.results['feature_info']['n_features']}")
        report.append(f"MQTT Alt Kategori Sayısı: {len(self.results['feature_info']['unique_labels'])}")
        report.append("")
        
        # MQTT Alt kategori dağılımı
        report.append("MQTT ALT KATEGORİ DAĞILIMI")
        report.append("-" * 40)
        for label, count in sorted(self.results['feature_info']['label_counts'].items()):
            percentage = (count / len(self.features)) * 100
            report.append(f"{label}: {count:,} örnek ({percentage:.2f}%)")
        report.append("")
        
        # Optimal k bulma
        report.append("OPTİMAL KÜME SAYISI")
        report.append("-" * 40)
        report.append(f"Optimal K: {self.results['optimal_k']}")
        report.append(f"Silhouette Score: {max(self.results['silhouette_scores']):.4f}")
        report.append("")
        
        # Kümeleme metrikleri
        report.append("KÜMELEME METRİKLERİ")
        report.append("-" * 40)
        metrics = self.results['clustering_metrics']
        report.append(f"Silhouette Score: {metrics['silhouette_score']:.4f}")
        report.append(f"Calinski-Harabasz Score: {metrics['calinski_harabasz_score']:.4f}")
        report.append(f"Davies-Bouldin Score: {metrics['davies_bouldin_score']:.4f}")
        report.append(f"Adjusted Rand Index: {metrics['adjusted_rand_index']:.4f}")
        report.append(f"Normalized Mutual Information: {metrics['normalized_mutual_info']:.4f}")
        report.append(f"Homogeneity Score: {metrics['homogeneity_score']:.4f}")
        report.append(f"Completeness Score: {metrics['completeness_score']:.4f}")
        report.append(f"V-Measure Score: {metrics['v_measure_score']:.4f}")
        report.append(f"Fowlkes-Mallows Index: {metrics['fowlkes_mallows_index']:.4f}")
        report.append("")
        
        # İstatistiksel testler
        if 'statistical_tests' in self.results:
            report.append("İSTATİSTİKSEL TESTLER")
            report.append("-" * 40)
            stats = self.results['statistical_tests']
            if 'f_statistic' in stats:
                report.append(f"F-istatistiği: {stats['f_statistic']:.4f}")
                report.append(f"P-değeri: {stats['p_value']:.6f}")
                report.append(f"İstatistiksel anlamlılık: {'Evet' if stats['significant'] else 'Hayır'} (α=0.05)")
            if 'cluster_stability' in stats:
                stability = stats['cluster_stability']
                report.append(f"Küme kararlılık skoru: {stability['mean_stability']:.4f} ± {stability['std_stability']:.4f}")
            report.append("")
        
        # Özellik önemlilik
        if 'feature_importance' in self.results:
            report.append("ÖZELLİK ÖNEMLİLİK ANALİZİ")
            report.append("-" * 40)
            feature_imp = self.results['feature_importance']
            report.append("En önemli 10 özellik (F-test):")
            for i, idx in enumerate(feature_imp['top_features_f'][:10]):
                feature_name = feature_imp['feature_names'][idx]
                f_score = feature_imp['f_scores'][idx]
                p_value = feature_imp['f_pvalues'][idx]
                report.append(f"  {i+1}. {feature_name}: F={f_score:.4f}, p={p_value:.6f}")
            report.append("")
            report.append("En önemli 10 özellik (Mutual Information):")
            for i, idx in enumerate(feature_imp['top_features_mi'][:10]):
                feature_name = feature_imp['feature_names'][idx]
                mi_score = feature_imp['mi_scores'][idx]
                report.append(f"  {i+1}. {feature_name}: MI={mi_score:.4f}")
            report.append("")
        
        # Küme analizi
        report.append("MQTT KÜME ANALİZİ")
        report.append("-" * 40)
        for cluster_id, analysis in self.results['cluster_analysis'].items():
            report.append(f"Küme {cluster_id}:")
            report.append(f"  En baskın etiket: {analysis['dominant_label']}")
            report.append(f"  Örnek sayısı: {analysis['total_samples']}")
            report.append(f"  Saflık: {analysis['purity']:.4f}")
            report.append(f"  Etiket dağılımı: {analysis['all_labels']}")
            report.append("")
        
        # Genel değerlendirme
        report.append("MQTT GENEL DEĞERLENDİRME")
        report.append("-" * 40)
        report.append(f"Genel Saflık: {self.results['overall_purity']:.4f}")
        
        # Sonuçların yorumlanması
        if self.results['overall_purity'] > 0.7:
            purity_assessment = "Yüksek - MQTT K-Means iyi performans gösteriyor"
        elif self.results['overall_purity'] > 0.5:
            purity_assessment = "Orta - MQTT K-Means orta düzeyde performans gösteriyor"
        else:
            purity_assessment = "Düşük - MQTT K-Means düşük performans gösteriyor"
        
        report.append(f"Saflık Değerlendirmesi: {purity_assessment}")
        report.append("")
        
        # MQTT özel bulgular
        report.append("MQTT ÖZEL BULGULAR")
        report.append("-" * 40)
        report.append("1. MQTT DDoS ve DoS alt kategorileri analiz edildi")
        report.append("2. Connect Flood ve Publish Flood ayrımı incelendi")
        report.append("3. Malformed Data kategorisi dahil edildi")
        report.append("4. MQTT protokolü özelinde kümeleme kalitesi değerlendirildi")
        report.append("")
        
        # Öneriler
        report.append("MQTT ÖNERİLER")
        report.append("-" * 40)
        report.append("1. MQTT protokol özelliklerine odaklanan özellik mühendisliği yapın")
        report.append("2. MQTT mesaj türlerini daha detaylı analiz edin")
        report.append("3. QoS seviyelerini kümeleme faktörü olarak değerlendirin")
        report.append("4. MQTT broker davranışlarını inceleyin")
        report.append("5. Gerçek zamanlı MQTT trafiği üzerinde test edin")
        
        # Raporu kaydet
        report_text = "\n".join(report)
        with open('/Volumes/KIOXIA/tasarım_proje_cıc_ıot/codes_5/mqtt_clustering_report.txt', 'w', encoding='utf-8') as f:
            f.write(report_text)
        
        print("MQTT detaylı rapor kaydedildi: mqtt_clustering_report.txt")
        return report_text
    
    def save_results_to_csv(self):
        """Sonuçları CSV dosyasına kaydet"""
        print("\n=== MQTT SONUÇLARI CSV'YE KAYDETME ===")
        
        # Sonuçları DataFrame'e çevir
        results_df = self.data.copy()
        results_df['cluster_id'] = self.cluster_labels
        results_df['predicted_label'] = [self.results['cluster_analysis'][cluster_id]['dominant_label'] 
                                       for cluster_id in self.cluster_labels]
        
        # CSV'ye kaydet
        results_df.to_csv('/Volumes/KIOXIA/tasarım_proje_cıc_ıot/codes_5/mqtt_clustering_results.csv', 
                         index=False)
        
        print("MQTT sonuçlar kaydedildi: mqtt_clustering_results.csv")
        
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
        cluster_stats_df.to_csv('/Volumes/KIOXIA/tasarım_proje_cıc_ıot/codes_5/mqtt_cluster_statistics.csv', 
                               index=False)
        
        print("MQTT küme istatistikleri kaydedildi: mqtt_cluster_statistics.csv")
    
    def run_complete_analysis(self):
        """Tam analiz sürecini çalıştır"""
        print("CIC-IoMT-2024 MQTT Alt Kategorileri K-Means Kümeleme Analizi Başlatılıyor...")
        
        try:
            # 1. Veri yükleme
            self.load_and_prepare_mqtt_data()
            
            # 2. Özellik hazırlama
            self.prepare_features()
            
            # 3. Etiketli veri görselleştirmesi (kümeleme öncesi)
            self.visualize_labeled_data()
            
            # 4. Optimal k bulma
            optimal_k = self.find_optimal_clusters()
            
            # 5. K-Means kümeleme
            self.perform_kmeans_clustering(optimal_k)
            
            # 6. Özellik önemlilik analizi
            self.analyze_feature_importance()
            
            # 7. Kümeleme sonuçları görselleştirmesi
            self.visualize_clustering_results()
            
            # 8. Ana görselleştirmeler
            self.create_visualizations()
            
            # 9. Gelişmiş görselleştirmeler
            self.create_advanced_visualizations()
            
            # 10. Rapor oluşturma
            self.create_detailed_report()
            
            # 11. Sonuçları kaydetme
            self.save_results_to_csv()
            
            print("\n" + "="*80)
            print("MQTT ANALİZİ TAMAMLANDI!")
            print("="*80)
            print("Oluşturulan dosyalar:")
            print("- mqtt_labeled_data_visualization.png (Etiketli veri görselleştirmesi)")
            print("- mqtt_clustering_results_visualization.png (Kümeleme sonuçları görselleştirmesi)")
            print("- mqtt_clustering_results.png (Ana görselleştirmeler)")
            print("- mqtt_advanced_visualizations.png (Gelişmiş görselleştirmeler - t-SNE, UMAP, dendrogram)")
            print("- mqtt_clustering_report.txt (Detaylı rapor)")
            print("- mqtt_clustering_results.csv (Sonuçlar)")
            print("- mqtt_cluster_statistics.csv (Küme istatistikleri)")
            
            return self.results
            
        except Exception as e:
            print(f"Hata oluştu: {e}")
            raise

def main():
    """Ana çalıştırma fonksiyonu"""
    data_path = "/Volumes/KIOXIA/tasarım_proje_cıc_ıot"
    
    # Analyzer'ı başlat
    analyzer = MQTTSubcategoryAnalyzerWithVisualization(data_path)
    
    # Tam analizi çalıştır
    results = analyzer.run_complete_analysis()
    
    return results

if __name__ == "__main__":
    main()
