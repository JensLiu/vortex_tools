import bisect
import re
from typing import Dict, List, Optional, Tuple

from .models import DumpInstruction


class DumpDatabase:
    def __init__(
        self,
        instructions: Dict[int, DumpInstruction],
        functions: List[Tuple[int, str]],
        function_ranges: List[Tuple[int, int, str]],
    ):
        self.instructions = instructions
        self.functions = functions
        self.function_ranges = function_ranges
        self.function_addr_map = {addr: name for addr, name in functions}
        self.function_range_starts = [start for start, _, _ in function_ranges]

    def find_function_by_pc(self, pc: int) -> Optional[str]:
        if not self.function_ranges:
            return None

        idx = bisect.bisect_right(self.function_range_starts, pc) - 1
        if idx < 0:
            return None

        start, end, name = self.function_ranges[idx]
        if start <= pc <= end:
            return name
        return None

    @classmethod
    def from_file(cls, dump_file: str) -> "DumpDatabase":
        func_header_re = re.compile(r"^\s*([0-9a-fA-F]+)\s+<([^>]+)>:\s*$")
        inst_re = re.compile(
            r"^\s*([0-9a-fA-F]+):\s+([0-9a-fA-F]{2}(?:\s+[0-9a-fA-F]{2}){1,7})\s+([^\s]+)(?:\s+(.*?))?\s*$"
        )
        target_re = re.compile(r"(0x[0-9a-fA-F]+)\s*<([^>]+)>")

        functions: List[Tuple[int, str]] = []
        function_ranges: List[Tuple[int, int, str]] = []
        instructions: Dict[int, DumpInstruction] = {}
        current_function: Optional[str] = None
        current_function_start: Optional[int] = None
        current_function_last_pc: Optional[int] = None

        def finalise_function_range() -> None:
            nonlocal current_function, current_function_start, current_function_last_pc
            if (
                current_function is not None
                and current_function_start is not None
                and current_function_last_pc is not None
            ):
                function_ranges.append(
                    (current_function_start, current_function_last_pc, current_function)
                )
            current_function = None
            current_function_start = None
            current_function_last_pc = None

        with open(dump_file, "r") as f:
            for raw_line in f:
                line = raw_line.rstrip("\n")

                fn_match = func_header_re.match(line)
                if fn_match:
                    finalise_function_range()
                    fn_addr = int(fn_match.group(1), 16)
                    fn_name = fn_match.group(2)
                    functions.append((fn_addr, fn_name))
                    current_function = fn_name
                    current_function_start = fn_addr
                    current_function_last_pc = None
                    continue

                inst_match = inst_re.match(line)
                if not inst_match:
                    # Non-disassembly lines terminate the current function block.
                    if current_function is not None:
                        finalise_function_range()
                    continue

                pc = int(inst_match.group(1), 16)
                raw_bytes = inst_match.group(2)
                mnemonic = inst_match.group(3)
                operands = (inst_match.group(4) or "").strip()

                target_addr = None
                target_name = None
                target_match = target_re.search(operands)
                if target_match:
                    target_addr = int(target_match.group(1), 16)
                    target_name = target_match.group(2)

                text = mnemonic if not operands else f"{mnemonic} {operands}"

                instructions[pc] = DumpInstruction(
                    pc=pc,
                    raw_bytes=raw_bytes,
                    mnemonic=mnemonic,
                    operands=operands,
                    text=text,
                    function=current_function,
                    target_addr=target_addr,
                    target_name=target_name,
                )

                if current_function is not None:
                    if current_function_start is None:
                        current_function_start = pc
                    current_function_last_pc = pc

        finalise_function_range()

        functions.sort(key=lambda x: x[0])
        function_ranges.sort(key=lambda x: x[0])
        return cls(
            instructions=instructions,
            functions=functions,
            function_ranges=function_ranges,
        )
