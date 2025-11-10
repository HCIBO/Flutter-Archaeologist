# Flutter Archaeologist 🏺

## 🎥 Live Demo / Démo en Direct

**Watch Flutter Archaeologist in action:**

[![ASCIIcast Demo](https://asciinema.org/a/example.png)](flutter_archaeologist_demo2.cast)

*Click the cast file to view in browser, or use:* `asciinema play flutter_archaeologist_demo2.cast`

## 📖 Overview / Aperçu

**English:**  
Flutter Archaeologist is an advanced reverse engineering framework specifically designed for Flutter applications. It provides a complete pipeline from binary analysis to intelligent Dart code reconstruction, enabling developers and researchers to understand, analyze, and recover Flutter app architectures.

**Français:**  
Flutter Archaeologist est un framework avancé de rétro-ingénierie spécialement conçu pour les applications Flutter. Il fournit un pipeline complet de l'analyse binaire à la reconstruction intelligente du code Dart, permettant aux développeurs et chercheurs de comprendre, analyser et récupérer les architectures d'applications Flutter.

---

## 🔵 Features / Fonctionnalités

### 1. **APK Extraction & Analysis / Extraction et Analyse APK**
⚪ **Smart Flutter Detection** - Automatically identifies Flutter applications and extracts relevant native libraries  
⚪ **Multi-Architecture Support** - Handles arm64-v8a, armeabi-v7a, x86_64 architectures simultaneously  
⚪ **Structured Extraction** - Organized temporary directory management with clean resource handling  
⚪ **Batch Processing** - Capable of processing multiple APK files in sequence  

### 2. **Dart Snapshot Extraction / Extraction des Snapshots Dart**
🔵 **Pattern Recognition** - Advanced binary pattern matching to locate Dart snapshot regions  
🔵 **Offset Analysis** - Precise memory offset calculation for snapshot boundaries  
🔵 **Multiple Format Support** - Compatible with various Flutter snapshot versions and formats  
🔵 **Smart Extraction** - Adaptive size detection and snapshot data recovery  

### 3. **Symbol Recovery / Récupération des Symboles**
⚪ **Class Reconstruction** - Recovers Dart class names, hierarchies, and structures through string analysis  
⚪ **Function Discovery** - Identifies method signatures, private/public functions, and entry points  
⚪ **Dynamic Symbol Analysis** - Uses nm tool and binary analysis to extract dynamic symbols  
⚪ **Dart VM Intelligence** - Detects Dart VM structures, type information, and runtime references  

### 4. **Widget Tree Analysis / Analyse de l'Arborescence des Widgets**
🔵 **Widget Categorization** - Intelligent classification into Pages, Buttons, Cards, Lists, Forms, Layouts, Dialogs  
🔵 **Hierarchy Reconstruction** - Builds parent-child relationships and widget tree structures  
🔵 **UI Pattern Recognition** - Identifies common Flutter UI patterns and design systems  
🔵 **Visual Reporting** - Generates tree diagrams and structural visualizations  

### 5. **Smart Code Reconstruction / Reconstruction Intelligente du Code**
⚪ **Context-Aware Analysis** - Understands code context and relationships between fragments  
⚪ **Fragment Merging** - Intelligently combines related code snippets into coherent structures  
⚪ **Import Inference** - Automatically detects and suggests required Dart imports and dependencies  
⚪ **Pattern Completion** - Completes partial code patterns based on Flutter framework conventions  

### 6. **Dart Code Generation / Génération de Code Dart**
🔵 **App Scaffolding** - Generates complete MaterialApp structure with routing and theming  
🔵 **Widget Generation** - Creates Stateless and Stateful widget classes from recovered symbols  
🔵 **Page Architecture** - Builds page and screen classes with proper StatefulWidget patterns  
🔵 **Model Classes** - Generates data model classes based on discovered structures  
🔵 **Comprehensive Documentation** - Produces detailed reports and reconstruction summaries  

---

## ⚪ Technical Highlights / Points Techniques

**English:**  
🔵 **Pure Python** - No external dependencies, uses system tools (binutils)  
🔵 **Modular Architecture** - Extensible class-based design for easy customization  
🔵 **Bilingual Output** - All reports and outputs available in both English and French  
🔵 **Multiple Formats** - JSON, text, and structured reporting for different use cases  
🔵 **Smart Algorithms** - Context-aware pattern matching and intelligent code reconstruction  

**Français:**  
🔵 **Python Pur** - Aucune dépendance externe, utilise les outils système (binutils)  
🔵 **Architecture Modulaire** - Conception basée sur des classes extensibles pour une personnalisation facile  
🔵 **Sortie Bilingue** - Tous les rapports et sorties disponibles en anglais et français  
🔵 **Formats Multiples** - Rapports JSON, texte et structurés pour différents cas d'utilisation  
🔵 **Algorithmes Intelligents** - Correspondance de motifs contextuelle et reconstruction intelligente du code  

---

## 🔵 Quick Start / Démarrage Rapide

```bash
# Install dependencies / Installer les dépendances
sudo apt-get install binutils  # Linux
brew install binutils         # macOS

# Run the tool / Exécuter l'outil
python flutter_decompiler_complete.py your_app.apk

# Specific modes / Modes spécifiques
python flutter_decompiler_complete.py your_app.apk --mode symbols
python flutter_decompiler_complete.py your_app.apk --mode widgets
python flutter_decompiler_complete.py your_app.apk --mode generate

---

## 🔵 Output Structure / Structure des Sorties

temp_extract/          # APK extraction
snapshots/             # Dart snapshots
dart_symbols/          # Symbol recovery
widget_analysis/       # Widget tree analysis
reconstructed_code/    # Code reconstruction
generated_code/        # Generated Dart code
