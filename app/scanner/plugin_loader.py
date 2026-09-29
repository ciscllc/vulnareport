"""
Lädt Plugins dynamisch aus dem PLUGIN_DIR. Vor jeder Aktivierung wird ein
sha256-Checksum der Datei gebildet; ändert sich der Dateiinhalt nach der
Aktivierung (z.B. durch nachträgliches Überschreiben auf der Platte), wird
das Plugin bei der nächsten Ausführung nicht mehr geladen, bis ein Admin es
erneut im Panel bestätigt. Das verhindert, dass ein Plugin nach der Prüfung
still ausgetauscht wird.
"""
import hashlib
import importlib.util
import os

from flask import current_app

from app.scanner.plugin_base import VulnPlugin


def file_checksum(path: str) -> str:
    with open(path, "rb") as f:
        return hashlib.sha256(f.read()).hexdigest()


def load_plugin_module(module_path: str):
    full_path = os.path.join(current_app.config["PLUGIN_DIR"], module_path)
    if not os.path.exists(full_path):
        raise FileNotFoundError(f"Plugin-Datei nicht gefunden: {module_path}")

    spec = importlib.util.spec_from_file_location(f"vulnreport_plugin_{module_path}", full_path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)

    if not hasattr(module, "Plugin"):
        raise AttributeError(f"Plugin-Datei {module_path} definiert keine Klasse 'Plugin'.")

    plugin_cls = module.Plugin
    if not issubclass(plugin_cls, VulnPlugin):
        raise TypeError(f"Plugin-Klasse in {module_path} muss von VulnPlugin erben.")

    return plugin_cls()


def load_enabled_plugins(plugin_records) -> list:
    """plugin_records: Liste von Plugin-DB-Objekten mit enabled=True.
    Prüft Checksum gegen den gespeicherten Wert; bei Mismatch wird das
    Plugin übersprungen (nicht automatisch deaktiviert, damit ein Admin
    bewusst reagieren muss)."""
    loaded = []
    for record in plugin_records:
        if not record.enabled:
            continue
        full_path = os.path.join(current_app.config["PLUGIN_DIR"], record.module_path)
        try:
            current_checksum = file_checksum(full_path)
        except FileNotFoundError:
            continue
        if record.checksum and current_checksum != record.checksum:
            # Datei wurde nach Aktivierung verändert - sicherheitshalber überspringen
            continue
        try:
            instance = load_plugin_module(record.module_path)
            loaded.append((record, instance))
        except Exception:
            continue
    return loaded
