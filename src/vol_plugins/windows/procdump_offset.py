# RAMBreaker bundled Volatility 3 plugin (installed by modules/installer.py).
# Licensed like Volatility 3 itself: Volatility Software License 1.0.
"""Dump the main executable of processes given by their EPROCESS address.

windows.pslist --pid only sees processes on the active list, and
windows.psscan --pid --dump re-scans the whole image to find them again
(> 30 min on a 34.5 GB image on a hard disk). RAMBreaker already has every
EPROCESS address from the case's psscan table, so this plugin builds the
object at that address and calls the standard PsList.process_dump.
"""
import logging

from volatility3.framework import exceptions, interfaces, renderers
from volatility3.framework.configuration import requirements
from volatility3.framework.renderers import format_hints
from volatility3.framework.symbols import intermed
from volatility3.framework.symbols.windows.extensions import pe
from volatility3.plugins.windows import pslist, psscan

vollog = logging.getLogger(__name__)


class ProcDumpOffset(interfaces.plugins.PluginInterface):
    """Dumps processes from EPROCESS addresses (e.g. from psscan), without a scan."""

    _required_framework_version = (2, 0, 0)
    _version = (1, 0, 0)

    @classmethod
    def get_requirements(cls):
        return [
            requirements.ModuleRequirement(name="kernel", description="Windows kernel",
                                           architectures=["Intel32", "Intel64"]),
            requirements.VersionRequirement(name="pslist", component=pslist.PsList,
                                            version=(3, 0, 0)),
            requirements.ListRequirement(name="offset", element_type=int,
                                         description="EPROCESS address(es) as psscan prints them "
                                                     "(kernel virtual, or physical with --physical)",
                                         optional=False),
            requirements.BooleanRequirement(name="physical", default=False, optional=True,
                                            description="Offsets are physical addresses"),
        ]

    def _generator(self):
        kernel = self.context.modules[self.config["kernel"]]
        pe_table = intermed.IntermediateSymbolTable.create(
            self.context, self.config_path, "windows", "pe", class_types=pe.class_types)
        for off in self.config["offset"]:
            status, pid, name = "Error outputting file", 0, ""
            try:
                if self.config.get("physical"):
                    layer = self.context.layers[kernel.layer_name].config["memory_layer"]
                    proc = self.context.object(kernel.symbol_table_name + "!_EPROCESS",
                                               layer_name=layer, offset=off)
                    proc = psscan.PsScan.virtual_process_from_physical(
                        self.context, self.config["kernel"], proc)
                else:
                    proc = self.context.object(kernel.symbol_table_name + "!_EPROCESS",
                                               layer_name=kernel.layer_name, offset=off)
                pid = int(proc.UniqueProcessId)
                name = proc.ImageFileName.cast("string", max_length=proc.ImageFileName.vol.count,
                                               errors="replace")
                try:            # process_dump swallows the reason; check readability first
                    pl = proc.add_process_layer()
                    peb = self.context.object(kernel.symbol_table_name + "!_PEB",
                                              layer_name=pl, offset=proc.Peb)
                    self.context.layers[pl].read(int(peb.ImageBaseAddress), 2)
                except exceptions.InvalidAddressException as e:
                    yield 0, (format_hints.Hex(off), pid, name,
                              f"not resident: {type(e).__name__} - the process image/PEB "
                              f"pages are not in this memory image")
                    continue
                fh = pslist.PsList.process_dump(self.context, kernel.symbol_table_name,
                                                pe_table, proc, self.open)
                if fh:
                    status = fh.preferred_filename
                    fh.close()
            except exceptions.InvalidAddressException as e:
                status = f"address not readable: {e}"
            except Exception as e:  # one bad offset must not stop the others
                status = f"error: {type(e).__name__}: {e}"
            yield 0, (format_hints.Hex(off), pid, name, status)

    def run(self):
        return renderers.TreeGrid([("Offset", format_hints.Hex), ("PID", int),
                                   ("ImageFileName", str), ("File output", str)],
                                  self._generator())
