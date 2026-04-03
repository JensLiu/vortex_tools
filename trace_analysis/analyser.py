import re
import sys
from typing import Dict, List, Optional, Tuple

from .dump_db import DumpDatabase
from .models import (
    AnalysedEvent,
    AnalysisReport,
    ComponentAnalysis,
    ComponentSummary,
    DumpInstruction,
    InstructionFlow,
    TraceRecord,
)
from .parsing import (
    find_first_available_int,
    parse_optional_int,
    parse_payload,
    summarise_data_fields,
)


class TraceAnalyser:
    TRACE_PATTERN = re.compile(
        r"^\s*(?:(?P<cycle>\d+):\s*)?(?P<component>[\w-]+):\s*(?P<payload>.*?)\s*\(#(?P<uuid>\d+)\)\s*$"
    )
    REQUIRED_FLOW_STAGES = {
        "schedule",
        "fetch.req",
        "fetch.rsp",
        "decode",
        "issue0-ibuffer",
        "issue0-dispatch",
        "commit",
    }

    def __init__(self, dump_db: DumpDatabase):
        self.dump_db = dump_db

    def parse_trace_line(self, line: str, line_no: int) -> Optional[TraceRecord]:
        match = self.TRACE_PATTERN.match(line)
        if not match:
            return None

        component = match.group("component")
        parts = component.split("-", 3)
        if len(parts) != 4:
            return None

        role, fields = parse_payload(match.group("payload"))
        cycle_str = match.group("cycle")
        cycle = int(cycle_str) if cycle_str is not None else None
        cluster, socket, core, event = parts

        wid = parse_optional_int(fields.get("wid"))
        pc = parse_optional_int(fields.get("PC"))
        tmask = fields.get("tmask")

        return TraceRecord(
            line_no=line_no,
            raw_line=line,
            cycle=cycle,
            cluster=cluster,
            socket=socket,
            core=core,
            event=event,
            role=role,
            wid=wid,
            pc=pc,
            tmask=tmask,
            uuid=int(match.group("uuid")),
            fields=fields,
        )

    def read_records_by_core(
        self, trace_file: str
    ) -> Dict[Tuple[str, str, str], List[TraceRecord]]:
        grouped: Dict[Tuple[str, str, str], List[TraceRecord]] = {}
        with open(trace_file, "r") as f:
            for line_no, raw_line in enumerate(f, start=1):
                line = raw_line.strip()
                if not line or line.startswith("***"):
                    continue
                record = self.parse_trace_line(line, line_no=line_no)
                if record is None:
                    continue
                if record.core_key not in grouped:
                    grouped[record.core_key] = []
                grouped[record.core_key].append(record)
        return grouped

    @staticmethod
    def _classify_instruction(inst: Optional[DumpInstruction]) -> Optional[str]:
        if inst is None:
            return None
        if inst.mnemonic == "ret":
            return "ret"
        if inst.mnemonic in ("jal", "jalr"):
            return "call"
        return None

    def analyse_component(
        self, key: Tuple[str, str, str], records: List[TraceRecord]
    ) -> ComponentAnalysis:
        events: List[AnalysedEvent] = []
        call_trace: List[str] = []
        instructions: List[InstructionFlow] = []
        unique_pcs = set()
        unknown_pc_count = 0
        call_count = 0
        ret_count = 0
        stage_event_counts: Dict[str, int] = {}

        cycles = [record.cycle for record in records if record.cycle is not None]
        first_cycle = min(cycles) if cycles else None
        last_cycle = max(cycles) if cycles else None

        events_by_uuid: Dict[int, List[TraceRecord]] = {}
        for record in records:
            if record.uuid == 0:
                continue
            if record.uuid not in events_by_uuid:
                events_by_uuid[record.uuid] = []
            events_by_uuid[record.uuid].append(record)

        for uuid, uuid_records in sorted(
            events_by_uuid.items(),
            key=lambda item: (
                item[1][0].cycle if item[1][0].cycle is not None else sys.maxsize,
                item[1][0].line_no,
            ),
        ):
            uuid_records_sorted = sorted(
                uuid_records,
                key=lambda r: (
                    r.cycle if r.cycle is not None else sys.maxsize,
                    r.line_no,
                ),
            )

            first_record = uuid_records_sorted[0]
            instruction_pc = first_record.pc
            if instruction_pc is None:
                instruction_pc = find_first_available_int(uuid_records_sorted, "PC")

            instruction_wid = first_record.wid
            if instruction_wid is None:
                instruction_wid = find_first_available_int(uuid_records_sorted, "wid")

            instruction_tmask = first_record.tmask
            if instruction_tmask is None:
                for rec in uuid_records_sorted:
                    if rec.tmask is not None:
                        instruction_tmask = rec.tmask
                        break

            inst = (
                self.dump_db.instructions.get(instruction_pc)
                if instruction_pc is not None
                else None
            )

            if instruction_pc is not None:
                unique_pcs.add(instruction_pc)

            if inst is None:
                if instruction_pc is None:
                    function_name = "<unknown-function>"
                    instruction_text = "<pc-missing>"
                else:
                    function_name = (
                        self.dump_db.find_function_by_pc(instruction_pc)
                        or "<unknown-function>"
                    )
                    instruction_text = "<instruction-not-found-in-dump>"
                    unknown_pc_count += 1
            else:
                function_name = (
                    inst.function
                    if inst.function is not None
                    else self.dump_db.find_function_by_pc(inst.pc)
                )
                if function_name is None:
                    function_name = "<unknown-function>"
                instruction_text = inst.text

            stages_seen: List[str] = []
            stage_seen_set = set()
            data_trace: List[str] = []
            analysed_events_for_uuid: List[AnalysedEvent] = []

            for record in uuid_records_sorted:
                stage = record.stage
                stage_event_counts[stage] = stage_event_counts.get(stage, 0) + 1
                if stage not in stage_seen_set:
                    stage_seen_set.add(stage)
                    stages_seen.append(stage)

                cycle_text = str(record.cycle) if record.cycle is not None else "?"
                data_summary = summarise_data_fields(record.fields)
                if data_summary:
                    data_trace.append(
                        f"line={record.line_no} cycle={cycle_text} stage={stage} | {data_summary}"
                    )

                kind = self._classify_instruction(inst)
                if kind == "call" and stage.startswith("commit"):
                    call_count += 1
                    target_fn = None
                    if inst is not None:
                        target_fn = inst.target_name
                        if target_fn is None and inst.target_addr is not None:
                            target_fn = self.dump_db.function_addr_map.get(inst.target_addr)
                    if target_fn is None:
                        target_fn = "<unknown-target>"
                    call_trace.append(
                        f"    line={record.line_no} cycle={cycle_text} CALL {function_name} -> {target_fn} uuid=#{uuid} pc={hex(instruction_pc) if instruction_pc is not None else '<unknown-pc>'}"
                    )
                elif kind == "ret" and stage.startswith("commit"):
                    ret_count += 1
                    call_trace.append(
                        f"    line={record.line_no} cycle={cycle_text} RET  {function_name} uuid=#{uuid} pc={hex(instruction_pc) if instruction_pc is not None else '<unknown-pc>'}"
                    )

                analysed_events_for_uuid.append(
                    AnalysedEvent(
                        line_no=record.line_no,
                        cycle=record.cycle,
                        uuid=record.uuid,
                        stage=stage,
                        event=record.event,
                        role=record.role,
                        wid=record.wid,
                        pc=record.pc,
                        tmask=record.tmask,
                        fields=dict(record.fields),
                        function_name=function_name,
                        instruction_text=instruction_text,
                        data_summary=data_summary,
                    )
                )

            uuid_cycles = [r.cycle for r in uuid_records_sorted if r.cycle is not None]
            uuid_first_cycle = min(uuid_cycles) if uuid_cycles else None
            uuid_last_cycle = max(uuid_cycles) if uuid_cycles else None

            is_stage_complete = self.REQUIRED_FLOW_STAGES.issubset(stage_seen_set)
            instructions.append(
                InstructionFlow(
                    order_index=len(instructions) + 1,
                    uuid=uuid,
                    wid=instruction_wid,
                    pc=instruction_pc,
                    tmask=instruction_tmask,
                    function_name=function_name,
                    instruction_text=instruction_text,
                    first_cycle=uuid_first_cycle,
                    last_cycle=uuid_last_cycle,
                    records_count=len(uuid_records_sorted),
                    stages=stages_seen,
                    is_stage_complete=is_stage_complete,
                    data_trace=data_trace,
                    events=analysed_events_for_uuid,
                )
            )
            events.extend(analysed_events_for_uuid)

        stage_complete_count = sum(1 for flow in instructions if flow.is_stage_complete)

        summary = ComponentSummary(
            event_count=len(records),
            instruction_count=len(instructions),
            first_cycle=first_cycle,
            last_cycle=last_cycle,
            stage_event_counts=stage_event_counts,
            stage_complete_count=stage_complete_count,
            unique_pcs=len(unique_pcs),
            call_count=call_count,
            ret_count=ret_count,
            unknown_pc_count=unknown_pc_count,
        )

        return ComponentAnalysis(
            key=key,
            summary=summary,
            instructions=instructions,
            events=events,
            call_trace=call_trace,
        )

    def analyse_trace(self, trace_file: str, dump_file: str) -> AnalysisReport:
        grouped = self.read_records_by_core(trace_file)
        components: List[ComponentAnalysis] = []
        for key in sorted(grouped.keys(), key=lambda k: (k[0], k[1], k[2])):
            records = grouped[key]
            components.append(self.analyse_component(key, records))

        return AnalysisReport(
            trace_file=trace_file,
            dump_file=dump_file,
            components=components,
        )
