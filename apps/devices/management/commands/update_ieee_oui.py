"""
Django management command to inspect or update VIGIL's local IEEE MAC OUI/MA-M/MA-S registry.
Usage:
  python manage.py update_ieee_oui --stats-only
  python manage.py update_ieee_oui
"""
from django.core.management.base import BaseCommand
from devices.oui_registry import IEEEOUIRegistry


class Command(BaseCommand):
    help = "Updates or inspects the local IEEE MAC OUI (MA-L /24, MA-M /28, MA-S /36) vendor database."

    def add_arguments(self, parser):
        parser.add_argument(
            "--stats-only",
            action="store_true",
            help="Display current loaded IEEE OUI database statistics without downloading from ieee.org.",
        )

    def handle(self, *args, **options):
        if options.get("stats_only"):
            stats = IEEEOUIRegistry.get_stats()
            self.stdout.write(
                self.style.SUCCESS(
                    f"VIGIL IEEE MAC Registry loaded: {stats['total_prefixes']} total prefixes "
                    f"(MA-L /24: {stats['ma_l_24_count']}, MA-M /28: {stats['ma_m_28_count']}, "
                    f"MA-S /36: {stats['ma_s_36_count']})."
                )
            )
            return

        self.stdout.write("Downloading latest IEEE MA-L, MA-M, and MA-S registries from standards-oui.ieee.org...")
        try:
            stats = IEEEOUIRegistry.update_from_ieee_csv()
            self.stdout.write(
                self.style.SUCCESS(
                    f"Successfully updated IEEE OUI database ({stats['downloaded_entries']} new/updated rows; "
                    f"total active prefixes: {stats['total_prefixes']})."
                )
            )
        except Exception as exc:
            stats = IEEEOUIRegistry.get_stats()
            self.stdout.write(
                self.style.WARNING(
                    f"Online IEEE download skipped ({exc}). Using local bundled IEEE registry "
                    f"({stats['total_prefixes']} prefixes active)."
                )
            )
