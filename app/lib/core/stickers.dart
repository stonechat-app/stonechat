/// Sticker packs are a purely client-side concept (PROTOCOL.md "Media"):
/// bundled asset packs, user-imported packs under `<docs>/stickers/<pack>/`,
/// and a local recents list. Nothing about packs ever touches the wire —
/// a sent sticker is an ordinary encrypted media blob.
library;

import 'dart:convert';
import 'dart:io';

import 'package:flutter/foundation.dart';
import 'package:flutter/painting.dart';
import 'package:flutter/services.dart';
import 'package:path/path.dart' as p;
import 'package:path_provider/path_provider.dart';

/// A pack is a named list of sticker refs. A ref is either
/// `asset:<bundle path>` (bundled) or an absolute file path (imported).
class StickerPack {
  final String name;
  final bool bundled;
  final List<String> refs;
  const StickerPack(
      {required this.name, required this.bundled, required this.refs});
}

class StickerStore extends ChangeNotifier {
  StickerStore._();
  static final instance = StickerStore._();

  static const _assetPrefix = 'asset:';
  static const _maxRecents = 24;
  static const _imageExts = {'.webp', '.png', '.jpg', '.jpeg'};

  List<StickerPack> packs = [];
  List<String> recents = [];
  bool _loaded = false;

  Future<void> load() async {
    if (_loaded) return;
    _loaded = true;
    await _reload();
  }

  Future<void> _reload() async {
    // Bundled packs: everything under assets/stickers/<pack>/.
    final manifest = await AssetManifest.loadFromAssetBundle(rootBundle);
    final byPack = <String, List<String>>{};
    for (final asset in manifest.listAssets()) {
      final parts = asset.split('/'); // assets/stickers/<pack>/<file>
      if (parts.length < 4 || parts[0] != 'assets' || parts[1] != 'stickers') {
        continue;
      }
      if (!_imageExts.contains(p.extension(asset).toLowerCase())) continue;
      (byPack[parts[2]] ??= []).add('$_assetPrefix$asset');
    }
    final loaded = <StickerPack>[
      for (final e in byPack.entries)
        StickerPack(name: _title(e.key), bundled: true, refs: e.value..sort()),
    ];

    // Imported packs: subdirectories of the on-device sticker root.
    final root = await _rootDir();
    await for (final entry in root.list()) {
      if (entry is! Directory) continue;
      final refs = <String>[
        await for (final f in entry.list())
          if (f is File &&
              _imageExts.contains(p.extension(f.path).toLowerCase()))
            f.path
      ]..sort();
      if (refs.isNotEmpty) {
        loaded.add(StickerPack(
            name: _title(p.basename(entry.path)), bundled: false, refs: refs));
      }
    }
    packs = loaded;

    // Recents, dropping refs whose backing file has since vanished.
    final recentsFile = File(p.join(root.path, 'recents.json'));
    if (await recentsFile.exists()) {
      try {
        final raw = jsonDecode(await recentsFile.readAsString());
        recents = [
          for (final r in (raw as List).whereType<String>())
            if (r.startsWith(_assetPrefix) || File(r).existsSync()) r
        ];
      } catch (_) {
        recents = [];
      }
    }
    notifyListeners();
  }

  Future<Directory> _rootDir() async {
    final docs = await getApplicationDocumentsDirectory();
    final dir = Directory(p.join(docs.path, 'stickers'));
    await dir.create(recursive: true);
    return dir;
  }

  static String _title(String s) =>
      s.isEmpty ? s : s[0].toUpperCase() + s.substring(1);

  ImageProvider imageFor(String ref) => ref.startsWith(_assetPrefix)
      ? AssetImage(ref.substring(_assetPrefix.length))
      : FileImage(File(ref)) as ImageProvider;

  /// A sendable file for [ref]; bundled assets are materialized to a stable
  /// temp file once (sendMedia copies it into the media dir anyway).
  Future<File> materialize(String ref) async {
    if (!ref.startsWith(_assetPrefix)) return File(ref);
    final asset = ref.substring(_assetPrefix.length);
    final dir = await getTemporaryDirectory();
    final file = File(p.join(dir.path, 'stonechat-sticker-${p.basename(asset)}'));
    if (!await file.exists()) {
      final data = await rootBundle.load(asset);
      await file.writeAsBytes(
          data.buffer.asUint8List(data.offsetInBytes, data.lengthInBytes));
    }
    return file;
  }

  /// Copy picked image files into the "Imported" pack.
  Future<void> importFiles(List<String> sourcePaths) async {
    final root = await _rootDir();
    final dir = Directory(p.join(root.path, 'imported'));
    await dir.create(recursive: true);
    for (final src in sourcePaths) {
      if (!_imageExts.contains(p.extension(src).toLowerCase())) continue;
      await File(src).copy(p.join(dir.path, p.basename(src)));
    }
    await _reload();
  }

  Future<void> recordRecent(String ref) async {
    recents.remove(ref);
    recents.insert(0, ref);
    if (recents.length > _maxRecents) {
      recents.removeRange(_maxRecents, recents.length);
    }
    final root = await _rootDir();
    await File(p.join(root.path, 'recents.json'))
        .writeAsString(jsonEncode(recents));
    notifyListeners();
  }
}
