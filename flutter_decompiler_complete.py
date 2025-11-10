import zipfile
import os
import argparse
import sys
import subprocess
import re
import json
from collections import defaultdict

class FlutterExtractor:
    def __init__(self):
        self.temp_dir = "temp_extract"
        
    def extract_apk(self, apk_path):
        try:
            print(f"🔵 Analyzing APK: {apk_path}")
            
            if not os.path.exists(self.temp_dir):
                os.makedirs(self.temp_dir)
            
            with zipfile.ZipFile(apk_path, 'r') as zip_ref:
                zip_ref.extractall(self.temp_dir)
            
            print("⚪ APK successfully extracted")
            
            self._list_all_libs()
            
            flutter_libs = self._find_flutter_libs()
            
            return flutter_libs
            
        except Exception as e:
            print(f"🔵 Error: {e}")
            return None
    
    def _list_all_libs(self):
        lib_path = os.path.join(self.temp_dir, "lib")
        print("\n🔵 ALL LIB FILES:")
        if os.path.exists(lib_path):
            for arch in os.listdir(lib_path):
                arch_path = os.path.join(lib_path, arch)
                if os.path.isdir(arch_path):
                    print(f"  🔵 {arch}:")
                    for file in os.listdir(arch_path):
                        print(f"     🔵 {file}")
    
    def _find_flutter_libs(self):
        lib_path = os.path.join(self.temp_dir, "lib")
        flutter_files = {}
        
        if os.path.exists(lib_path):
            for arch in os.listdir(lib_path):
                arch_path = os.path.join(lib_path, arch)
                if os.path.isdir(arch_path):
                    for file in os.listdir(arch_path):
                        if file.endswith('.so'):
                            full_path = os.path.join(arch_path, file)
                            flutter_files[f"{arch}/{file}"] = full_path
        
        return flutter_files

class SnapshotExtractor:
    def __init__(self):
        self.temp_dir = "temp_extract"
    
    def extract_snapshot(self, app_so_path, output_dir="snapshots"):
        if not os.path.exists(output_dir):
            os.makedirs(output_dir)
        
        print(f"🔵 Snapshot extraction: {app_so_path}")
        
        offsets = self._find_snapshot_offsets(app_so_path)
        
        extracted = self._extract_snapshots(app_so_path, offsets, output_dir)
        
        return extracted
    
    def _find_snapshot_offsets(self, file_path):
        print("🔵 Searching for snapshot regions...")
        
        with open(file_path, 'rb') as f:
            data = f.read()
        
        patterns = [
            b'kFlutterSnapshotData',
            b'DartSnapshot',
            b'FLUTTER_SNAPSHOT',
            b'_kDartVmSnapshotData',
            b'_kDartIsolateSnapshotData'
        ]
        
        offsets = {}
        for pattern in patterns:
            start = 0
            while True:
                pos = data.find(pattern, start)
                if pos == -1:
                    break
                offsets[f"0x{pos:08x}_{pattern.decode('utf-8', errors='ignore')}"] = pos
                start = pos + 1
        
        print(f"🔵 Found offsets: {len(offsets)}")
        for name, offset in offsets.items():
            print(f"   ⚪ {name}")
        
        return offsets
    
    def _extract_snapshots(self, file_path, offsets, output_dir):
        print("🔵 Extracting snapshots...")
        
        with open(file_path, 'rb') as f:
            data = f.read()
        
        extracted_files = []
        
        for name, offset in offsets.items():
            for size in [100000, 500000, 1000000, 5000000, 10000000]:
                end_offset = min(offset + size, len(data))
                snapshot_data = data[offset:end_offset]
                
                output_path = os.path.join(output_dir, f"snapshot_{name}.bin")
                with open(output_path, 'wb') as f:
                    f.write(snapshot_data)
                
                extracted_files.append(output_path)
                print(f"   ⚪ Saved: {output_path} ({len(snapshot_data)} bytes)")
                break
        
        return extracted_files

class DartSymbolRecovery:
    def __init__(self):
        self.symbols_dir = "dart_symbols"
    
    def recover_symbols(self, app_so_path):
        print(f"🔵 Symbol Recovery: {app_so_path}")
        
        if not os.path.exists(self.symbols_dir):
            os.makedirs(self.symbols_dir)
        
        symbols = self._extract_symbols_from_strings(app_so_path)
        
        dynamic_symbols = self._extract_dynamic_symbols(app_so_path)
        
        dart_structures = self._find_dart_structures(app_so_path)
        
        all_findings = {
            'strings_symbols': symbols,
            'dynamic_symbols': dynamic_symbols,
            'dart_structures': dart_structures
        }
        
        self._save_findings(all_findings, os.path.basename(app_so_path))
        
        return all_findings
    
    def _extract_symbols_from_strings(self, file_path):
        print("🔵 Performing strings analysis...")
        
        try:
            result = subprocess.run(['strings', '-n', '4', file_path], 
                                  capture_output=True, text=True)
            all_strings = result.stdout.split('\n')
            
            dart_patterns = {
                'classes': [],
                'functions': [],
                'libraries': [],
                'widgets': [],
                'packages': []
            }
            
            for string in all_strings:
                if not string.strip():
                    continue
                    
                if re.match(r'^[A-Z][a-zA-Z0-9_]*$', string) and len(string) > 3:
                    if string.endswith('Widget') or string.endswith('Page') or string.endswith('Screen'):
                        dart_patterns['widgets'].append(string)
                    else:
                        dart_patterns['classes'].append(string)
                
                elif re.match(r'^[a-z][a-zA-Z0-9_]*$', string) and len(string) > 5:
                    if string.startswith('_'):
                        dart_patterns['functions'].append(f"private: {string}")
                    else:
                        dart_patterns['functions'].append(string)
                
                elif 'dart:' in string or 'package:' in string:
                    dart_patterns['libraries'].append(string)
                elif '/' in string and ('.dart' in string or string.count('/') > 1):
                    dart_patterns['packages'].append(string)
            
            for key in dart_patterns:
                dart_patterns[key] = sorted(list(set(dart_patterns[key])))
            
            print(f"⚪ Strings analysis completed:")
            print(f"   🔵 Classes: {len(dart_patterns['classes'])}")
            print(f"   🔵 Functions: {len(dart_patterns['functions'])}")
            print(f"   🔵 Libraries: {len(dart_patterns['libraries'])}")
            print(f"   🔵 Widgets: {len(dart_patterns['widgets'])}")
            
            return dart_patterns
            
        except Exception as e:
            print(f"🔵 Strings analysis error: {e}")
            return {}
    
    def _extract_dynamic_symbols(self, file_path):
        print("🔵 Searching for dynamic symbols...")
        
        try:
            result = subprocess.run(['nm', '-D', file_path], 
                                  capture_output=True, text=True)
            
            symbols = []
            for line in result.stdout.split('\n'):
                if ' T ' in line:
                    symbol = line.split(' T ')[-1].strip()
                    if symbol and not symbol.startswith('_'):
                        symbols.append(symbol)
            
            print(f"⚪ Dynamic symbols: {len(symbols)}")
            return symbols[:50]
            
        except Exception as e:
            print(f"🔵 NM tool error: {e}")
            return []
    
    def _find_dart_structures(self, file_path):
        print("🔵 Searching for Dart structures...")
        
        try:
            result = subprocess.run(['strings', '-n', '10', file_path], 
                                  capture_output=True, text=True)
            
            structures = {
                'vm_entries': [],
                'snapshot_refs': [],
                'type_info': []
            }
            
            for line in result.stdout.split('\n'):
                line = line.strip()
                if not line:
                    continue
                
                if 'Dart_' in line:
                    structures['vm_entries'].append(line)
                elif 'Snapshot' in line or 'snapshot' in line.lower():
                    structures['snapshot_refs'].append(line)
                elif 'Type' in line and len(line) < 100:
                    structures['type_info'].append(line)
            
            print(f"⚪ Dart structures found:")
            print(f"   🔵 VM Entries: {len(structures['vm_entries'])}")
            print(f"   🔵 Snapshot Refs: {len(structures['snapshot_refs'])}")
            print(f"   🔵 Type Info: {len(structures['type_info'])}")
            
            return structures
            
        except Exception as e:
            print(f"🔵 Structure analysis error: {e}")
            return {}
    
    def _save_findings(self, findings, filename):
        output_file = os.path.join(self.symbols_dir, f"{filename}_symbols.json")
        
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(findings, f, indent=2, ensure_ascii=False)
        
        summary_file = os.path.join(self.symbols_dir, f"{filename}_summary.txt")
        with open(summary_file, 'w', encoding='utf-8') as f:
            f.write("FLUTTER DECOMPILER - SYMBOL RECOVERY REPORT\n")
            f.write("=" * 50 + "\n\n")
            
            if 'strings_symbols' in findings:
                symbols = findings['strings_symbols']
                f.write(f"CLASSES ({len(symbols.get('classes', []))}):\n")
                for cls in symbols.get('classes', [])[:20]:
                    f.write(f"   • {cls}\n")
                
                f.write(f"\nWIDGETS ({len(symbols.get('widgets', []))}):\n")
                for widget in symbols.get('widgets', [])[:15]:
                    f.write(f"   • {widget}\n")
                
                f.write(f"\nFUNCTIONS ({len(symbols.get('functions', []))}):\n")
                for func in symbols.get('functions', [])[:20]:
                    f.write(f"   • {func}\n")
        
        print(f"⚪ Reports saved:")
        print(f"   🔵 {output_file}")
        print(f"   🔵 {summary_file}")

class WidgetTreeBuilder:
    def __init__(self):
        self.widgets_dir = "widget_analysis"
    
    def analyze_widgets(self, symbols_json_path):
        print(f"🔵 Widget Analysis: {symbols_json_path}")
        
        if not os.path.exists(self.widgets_dir):
            os.makedirs(self.widgets_dir)
        
        with open(symbols_json_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
        
        widgets = data.get('strings_symbols', {}).get('widgets', [])
        classes = data.get('strings_symbols', {}).get('classes', [])
        functions = data.get('strings_symbols', {}).get('functions', [])
        
        categorized = self._categorize_widgets(widgets, classes)
        
        widget_tree = self._build_widget_tree(categorized)
        
        self._generate_widget_report(categorized, widget_tree, os.path.basename(symbols_json_path))
        
        return categorized, widget_tree
    
    def _categorize_widgets(self, widgets, all_classes):
        categories = {
            'pages': [],
            'screens': [],
            'buttons': [],
            'cards': [],
            'lists': [],
            'forms': [],
            'layouts': [],
            'dialogs': [],
            'others': []
        }
        
        all_potential_widgets = widgets + [cls for cls in all_classes if self._is_likely_widget(cls)]
        
        for widget in all_potential_widgets:
            widget_lower = widget.lower()
            
            if any(word in widget_lower for word in ['page', 'screen', 'view']):
                categories['pages'].append(widget)
            
            elif any(word in widget_lower for word in ['button', 'btn', 'fab']):
                categories['buttons'].append(widget)
            
            elif any(word in widget_lower for word in ['card', 'tile']):
                categories['cards'].append(widget)
            
            elif any(word in widget_lower for word in ['list', 'grid', 'table']):
                categories['lists'].append(widget)
            
            elif any(word in widget_lower for word in ['form', 'field', 'input', 'textfield']):
                categories['forms'].append(widget)
            
            elif any(word in widget_lower for word in ['layout', 'container', 'column', 'row', 'stack']):
                categories['layouts'].append(widget)
            
            elif any(word in widget_lower for word in ['dialog', 'modal', 'alert', 'popup']):
                categories['dialogs'].append(widget)
            
            else:
                categories['others'].append(widget)
        
        return categories
    
    def _is_likely_widget(self, class_name):
        widget_indicators = [
            'widget', 'page', 'screen', 'view', 'button', 'card', 
            'list', 'grid', 'dialog', 'menu', 'bar', 'header', 'footer'
        ]
        
        class_lower = class_name.lower()
        return any(indicator in class_lower for indicator in widget_indicators)
    
    def _build_widget_tree(self, categorized):
        tree = defaultdict(list)
        
        for page in categorized['pages']:
            possible_children = []
            
            if categorized['buttons']:
                possible_children.extend(categorized['buttons'][:3])
            
            if categorized['cards']:
                possible_children.extend(categorized['cards'][:2])
            
            if categorized['lists']:
                possible_children.extend(categorized['lists'][:2])
            
            tree[page] = possible_children
        
        return tree
    
    def _generate_widget_report(self, categorized, widget_tree, filename):
        report_file = os.path.join(self.widgets_dir, f"widget_analysis_{filename.replace('.json', '')}.txt")
        
        with open(report_file, 'w', encoding='utf-8') as f:
            f.write("FLUTTER WIDGET TREE ANALYSIS REPORT\n")
            f.write("=" * 60 + "\n\n")
            
            f.write("WIDGET CATEGORIES:\n")
            f.write("-" * 30 + "\n")
            for category, items in categorized.items():
                f.write(f"{category.upper():12} : {len(items):3} items\n")
            
            f.write("\n\nWIDGET TREE STRUCTURE:\n")
            f.write("-" * 40 + "\n")
            for parent, children in widget_tree.items():
                f.write(f"\n{parent}:\n")
                for child in children:
                    f.write(f"   └── {child}\n")
            
            f.write("\n\nDETAILED WIDGET LIST:\n")
            f.write("-" * 30 + "\n")
            for category, items in categorized.items():
                if items:
                    f.write(f"\n{category.upper()}:\n")
                    for item in items[:15]:
                        f.write(f"   • {item}\n")
                    if len(items) > 15:
                        f.write(f"   ... and {len(items) - 15} more\n")
        
        print(f"⚪ Widget analysis report: {report_file}")
        
        json_file = os.path.join(self.widgets_dir, f"widget_tree_{filename.replace('.json', '')}.json")
        with open(json_file, 'w', encoding='utf-8') as f:
            json.dump({
                'categorized_widgets': categorized,
                'widget_tree': dict(widget_tree)
            }, f, indent=2, ensure_ascii=False)
        
        print(f"⚪ Widget tree JSON: {json_file}")

class SmartDartReconstructor:
    def __init__(self):
        self.temp_dir = "temp_extract"
        self.output_dir = "reconstructed_code"
    
    def reconstruct_dart_code(self):
        print("🔵 Smart Dart Code Reconstruction...")
        
        if not os.path.exists(self.output_dir):
            os.makedirs(self.output_dir)
        
        libapp_path = "temp_extract/lib/arm64-v8a/libapp.so"
        all_strings = self._extract_all_strings(libapp_path)
        
        if not all_strings:
            print("🔵 No strings found!")
            return
        
        reconstructed = self._smart_reconstruction(all_strings)
        
        self._generate_reconstruction_report(reconstructed)
        
        return reconstructed
    
    def _extract_all_strings(self, libapp_path):
        try:
            import subprocess
            result = subprocess.run(['strings', '-n', '4', libapp_path], 
                                  capture_output=True, text=True)
            return [s.strip() for s in result.stdout.split('\n') if s.strip()]
        except Exception as e:
            print(f"🔵 Strings extraction failed: {e}")
            return []
    
    def _smart_reconstruction(self, all_strings):
        print("   🔵 Smart pattern matching...")
        
        reconstructed = {
            'widget_tree': [],
            'method_fragments': [],
            'class_fragments': [],
            'import_hints': [],
            'ui_context': [],
            'build_patterns': []
        }
        
        context_buffer = ""
        
        for i, string in enumerate(all_strings):
            if len(string) < 3:
                continue
            
            if self._is_widget_related(string):
                reconstructed['widget_tree'].append(string)
            
            if self._is_method_fragment(string):
                reconstructed['method_fragments'].append(string)
            
            if self._is_class_fragment(string):
                reconstructed['class_fragments'].append(string)
            
            if any(pkg in string for pkg in ['package:', 'dart:', 'flutter/', 'material']):
                reconstructed['import_hints'].append(string)
            
            if self._is_ui_context(string):
                reconstructed['ui_context'].append(string)
            
            if 'build' in string.lower() and any(ctx in string for ctx in ['context', 'Widget', 'return']):
                reconstructed['build_patterns'].append(string)
            
            if i > 0 and self._could_be_related(context_buffer, string):
                context_buffer += " " + string
                if len(context_buffer) > 100:
                    if self._looks_like_code(context_buffer):
                        reconstructed['method_fragments'].append(context_buffer)
                    context_buffer = ""
            else:
                context_buffer = string
        
        return reconstructed
    
    def _is_widget_related(self, string):
        widget_indicators = [
            'Widget', 'Page', 'Screen', 'View', 'Dialog', 'Menu', 'Bar',
            'Button', 'Card', 'List', 'Grid', 'AppBar', 'Scaffold', 'Container'
        ]
        return any(indicator in string for indicator in widget_indicators)
    
    def _is_method_fragment(self, string):
        method_indicators = ['void', 'Future', 'async', 'await', 'return', '=>']
        return any(indicator in string for indicator in method_indicators)
    
    def _is_class_fragment(self, string):
        class_indicators = ['class', 'extends', 'implements', 'with', 'Stateful', 'Stateless']
        return any(indicator in string for indicator in class_indicators)
    
    def _is_ui_context(self, string):
        return (20 < len(string) < 200 and 
                not string.startswith('!!!') and 
                not string.isupper())
    
    def _could_be_related(self, prev, current):
        if not prev or not current:
            return False
        
        common_words = ['build', 'Widget', 'context', 'return', 'void']
        return any(word in prev and word in current for word in common_words)
    
    def _looks_like_code(self, text):
        code_indicators = ['()', '{}', ';', '=>', 'return', 'void', 'class']
        return sum(1 for indicator in code_indicators if indicator in text) >= 2
    
    def _generate_reconstruction_report(self, reconstructed):
        report_file = os.path.join(self.output_dir, "smart_reconstruction.txt")
        
        with open(report_file, 'w', encoding='utf-8') as f:
            f.write("SMART DART CODE RECONSTRUCTION REPORT\n")
            f.write("=" * 65 + "\n\n")
            
            if reconstructed['widget_tree']:
                f.write("WIDGET TREE FRAGMENTS:\n")
                f.write("-" * 40 + "\n")
                for widget in reconstructed['widget_tree'][:20]:
                    f.write(f"{widget}\n")
            
            if reconstructed['class_fragments']:
                f.write("\nCLASS FRAGMENTS:\n")
                f.write("-" * 30 + "\n")
                for cls in reconstructed['class_fragments'][:15]:
                    f.write(f"{cls}\n")
            
            if reconstructed['method_fragments']:
                f.write("\nMETHOD FRAGMENTS:\n")
                f.write("-" * 30 + "\n")
                for method in reconstructed['method_fragments'][:15]:
                    f.write(f"{method}\n")
            
            if reconstructed['build_patterns']:
                f.write("\nBUILD METHOD PATTERNS:\n")
                f.write("-" * 35 + "\n")
                for build in reconstructed['build_patterns'][:10]:
                    f.write(f"{build}\n")
            
            if reconstructed['ui_context']:
                f.write("\nUI CONTEXT & TEXTS:\n")
                f.write("-" * 30 + "\n")
                for ui in reconstructed['ui_context'][:20]:
                    f.write(f"{ui}\n")
            
            if reconstructed['import_hints']:
                f.write("\nIMPORT HINTS:\n")
                f.write("-" * 25 + "\n")
                for imp in reconstructed['import_hints'][:10]:
                    f.write(f"{imp}\n")
            
            f.write(f"\nRECONSTRUCTION STATISTICS:\n")
            f.write("-" * 35 + "\n")
            for category, items in reconstructed.items():
                f.write(f"   {category.upper():20}: {len(items):4} items\n")
        
        print(f"⚪ Smart reconstruction report: {report_file}")
        
        json_file = os.path.join(self.output_dir, "smart_reconstruction.json")
        with open(json_file, 'w', encoding='utf-8') as f:
            json.dump(reconstructed, f, indent=2, ensure_ascii=False)
        
        print(f"⚪ JSON export: {json_file}")

class DartCodeGenerator:
    def __init__(self):
        self.recon_dir = "reconstructed_code"
        self.output_dir = "generated_code"
    
    def generate_dart_code(self):
        print("🔵 Generating Pseudo-Dart Code...")
        
        if not os.path.exists(self.output_dir):
            os.makedirs(self.output_dir)
        
        json_path = os.path.join(self.recon_dir, "smart_reconstruction.json")
        if not os.path.exists(json_path):
            print("🔵 Reconstruction JSON not found!")
            return
        
        with open(json_path, 'r', encoding='utf-8') as f:
            reconstructed = json.load(f)
        
        generated_code = self._generate_from_fragments(reconstructed)
        
        self._write_generated_code(generated_code)
        
        return generated_code
    
    def _generate_from_fragments(self, reconstructed):
        print("   🔵 Generating code from fragments...")
        
        generated = {
            'main_app': self._generate_main_app(reconstructed),
            'widgets': self._generate_widget_classes(reconstructed),
            'pages': self._generate_page_classes(reconstructed),
            'models': self._generate_model_classes(reconstructed),
            'summary': self._generate_summary(reconstructed)
        }
        
        return generated
    
    def _generate_main_app(self, reconstructed):
        main_app = """import 'package:flutter/material.dart';

void main() {
  runApp(MyApp());
}

class MyApp extends StatelessWidget {
  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: 'Generated Flutter App',
      theme: ThemeData(
        primarySwatch: Colors.blue,
      ),
      home: MainPage(),
      routes: {
      },
    );
  }
}
"""
        return main_app
    
    def _generate_widget_classes(self, reconstructed):
        widgets = []
        
        widget_fragments = reconstructed.get('widget_tree', [])
        
        unique_widgets = set()
        for fragment in widget_fragments:
            words = fragment.split()
            for word in words:
                if word.endswith('Widget') or word.endswith('Page') or word.endswith('Screen'):
                    unique_widgets.add(word)
        
        for widget_name in list(unique_widgets)[:10]:
            widget_code = f"""
class {widget_name} extends StatelessWidget {{
  @override
  Widget build(BuildContext context) {{
    return Container(
      child: Text('{widget_name} Placeholder'),
    );
  }}
}}
"""
            widgets.append(widget_code)
        
        return "\n".join(widgets)
    
    def _generate_page_classes(self, reconstructed):
        pages = []
        
        page_indicators = ['Page', 'Screen', 'View']
        page_fragments = [f for f in reconstructed.get('widget_tree', []) 
                         if any(indicator in f for indicator in page_indicators)]
        
        unique_pages = set()
        for fragment in page_fragments:
            words = fragment.split()
            for word in words:
                if any(indicator in word for indicator in page_indicators):
                    unique_pages.add(word)
        
        for page_name in list(unique_pages)[:5]:
            page_code = f"""
class {page_name} extends StatefulWidget {{
  @override
  _{page_name}State createState() => _{page_name}State();
}}

class _{page_name}State extends State<{page_name}> {{
  @override
  Widget build(BuildContext context) {{
    return Scaffold(
      appBar: AppBar(
        title: Text('{page_name}'),
      ),
      body: Center(
        child: Text('{page_name} Content'),
      ),
    );
  }}
}}
"""
            pages.append(page_code)
        
        return "\n".join(pages)
    
    def _generate_model_classes(self, reconstructed):
        models = []
        
        class_fragments = reconstructed.get('class_fragments', [])
        
        for i, fragment in enumerate(class_fragments[:5]):
            class_name = f"Model{i+1}"
            model_code = f"""
class {class_name} {{
  final String id;
  final String name;
  
  {class_name}({{
    required this.id,
    required this.name,
  }});
  
}}
"""
            models.append(model_code)
        
        return "\n".join(models)
    
    def _generate_summary(self, reconstructed):
        stats = {
            'total_widgets': len(reconstructed.get('widget_tree', [])),
            'total_methods': len(reconstructed.get('method_fragments', [])),
            'total_classes': len(reconstructed.get('class_fragments', [])),
            'total_imports': len(reconstructed.get('import_hints', [])),
            'ui_strings': len(reconstructed.get('ui_context', []))
        }
        
        summary = f"""FLUTTER APP RECONSTRUCTION SUMMARY

STATISTICS:
- Widgets: {stats['total_widgets']}
- Methods: {stats['total_methods']} 
- Classes: {stats['total_classes']}
- Import Hints: {stats['total_imports']}
- UI Strings: {stats['ui_strings']}

DETECTED PATTERNS:
- MaterialApp structure
- Multiple Page/Screen classes
- Stateless and Stateful widgets
- Basic app architecture

NOTE: This is generated code based on binary analysis
Actual implementation may vary.
"""
        return summary
    
    def _write_generated_code(self, generated_code):
        main_file = os.path.join(self.output_dir, "main.dart")
        with open(main_file, 'w', encoding='utf-8') as f:
            f.write(generated_code['main_app'])
            f.write("\n\n")
            f.write(generated_code['widgets'])
            f.write("\n\n")
            f.write(generated_code['pages'])
            f.write("\n\n")
            f.write(generated_code['models'])
        
        summary_file = os.path.join(self.output_dir, "SUMMARY.md")
        with open(summary_file, 'w', encoding='utf-8') as f:
            f.write(generated_code['summary'])
        
        widgets_file = os.path.join(self.output_dir, "widgets.dart")
        with open(widgets_file, 'w', encoding='utf-8') as f:
            f.write(generated_code['widgets'])
        
        print(f"⚪ Generated main.dart: {main_file}")
        print(f"⚪ Generated summary: {summary_file}")
        print(f"⚪ Generated widgets: {widgets_file}")

def main():
    parser = argparse.ArgumentParser(description='Flutter Decompiler - Complete Tool')
    parser.add_argument('apk_path', help='Path to APK file')
    parser.add_argument('--mode', choices=['extract', 'snapshot', 'symbols', 'widgets', 'reconstruct', 'generate', 'all'], 
                       default='all', help='Execution mode')
    
    args = parser.parse_args()
    
    if not os.path.exists(args.apk_path):
        print(f"🔵 APK file not found!: {args.apk_path}")
        sys.exit(1)
    
    if args.mode in ['extract', 'snapshot', 'symbols', 'widgets', 'reconstruct', 'generate', 'all']:
        extractor = FlutterExtractor()
        libs = extractor.extract_apk(args.apk_path)
        
        if not libs:
            print("🔵 No libs found!")
            return
    
    if args.mode in ['snapshot', 'all']:
        for lib_name, lib_path in libs.items():
            if 'libapp.so' in lib_name:
                print(f"\n{'='*60}")
                print(f"🔵 SNAPSHOT EXTRACTION: {lib_name}")
                print(f"{'='*60}")
                snapshot_extractor = SnapshotExtractor()
                snapshots = snapshot_extractor.extract_snapshot(lib_path)
                if snapshots:
                    print(f"⚪ {len(snapshots)} snapshots extracted!")
    
    if args.mode in ['symbols', 'widgets', 'reconstruct', 'generate', 'all']:
        for lib_name, lib_path in libs.items():
            if 'libapp.so' in lib_name:
                print(f"\n{'='*60}")
                print(f"🔵 SYMBOL RECOVERY: {lib_name}")
                print(f"{'='*60}")
                symbol_recovery = DartSymbolRecovery()
                findings = symbol_recovery.recover_symbols(lib_path)
                if findings:
                    print(f"⚪ Symbol recovery completed!")
    
    if args.mode in ['widgets', 'reconstruct', 'generate', 'all']:
        symbols_dir = "dart_symbols"
        if os.path.exists(symbols_dir):
            json_files = [f for f in os.listdir(symbols_dir) if f.endswith('_symbols.json')]
            if json_files:
                widget_analyzer = WidgetTreeBuilder()
                for json_file in json_files:
                    json_path = os.path.join(symbols_dir, json_file)
                    print(f"\n{'='*60}")
                    print(f"🔵 WIDGET ANALYSIS: {json_file}")
                    print(f"{'='*60}")
                    categorized, tree = widget_analyzer.analyze_widgets(json_path)
                    print(f"⚪ Widget analysis completed!")
    
    if args.mode in ['reconstruct', 'generate', 'all']:
        print(f"\n{'='*60}")
        print(f"🔵 SMART RECONSTRUCTION")
        print(f"{'='*60}")
        reconstructor = SmartDartReconstructor()
        reconstruction_results = reconstructor.reconstruct_dart_code()
        if reconstruction_results:
            print(f"⚪ Smart reconstruction completed!")
    
    if args.mode in ['generate', 'all']:
        print(f"\n{'='*60}")
        print(f"🔵 CODE GENERATION")
        print(f"{'='*60}")
        generator = DartCodeGenerator()
        generation_results = generator.generate_dart_code()
        if generation_results:
            print(f"⚪ CODE GENERATION COMPLETED!")
    
    print(f"\n⚪ All operations completed!")
    print("👉 Check the generated folders:")
    print("   - temp_extract/ (APK extraction)")
    print("   - snapshots/ (Dart snapshots)")
    print("   - dart_symbols/ (Symbol recovery)")
    print("   - widget_analysis/ (Widget analysis)")
    print("   - reconstructed_code/ (Code reconstruction)")
    print("   - generated_code/ (Generated Dart code)")

if __name__ == "__main__":
    main()