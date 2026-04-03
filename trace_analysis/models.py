from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple


def normalise_stage(event: str, role: Optional[str]) -> str:
    base = event.strip().lower()
    if role is None:
        return base
    role_norm = role.strip().lower().replace(" ", "-")
    return f"{base}.{role_norm}"


@dataclass(frozen=True)
class TraceRecord:
    line_no: int
    raw_line: str
    cycle: Optional[int]
    cluster: str
    socket: str
    core: str
    event: str
    role: Optional[str]
    wid: Optional[int]
    pc: Optional[int]
    tmask: Optional[str]
    uuid: int
    fields: Dict[str, str]

    @property
    def component_key(self) -> Tuple[str, str, str, int]:
        wid = self.wid if self.wid is not None else -1
        return (self.cluster, self.socket, self.core, wid)

    @property
    def core_key(self) -> Tuple[str, str, str]:
        return (self.cluster, self.socket, self.core)

    @property
    def stage(self) -> str:
        return normalise_stage(self.event, self.role)


@dataclass(frozen=True)
class DumpInstruction:
    pc: int
    raw_bytes: str
    mnemonic: str
    operands: str
    text: str
    function: Optional[str]
    target_addr: Optional[int]
    target_name: Optional[str]


@dataclass(frozen=True)
class AnalysedEvent:
    line_no: int
    cycle: Optional[int]
    uuid: int
    stage: str
    event: str
    role: Optional[str]
    wid: Optional[int]
    pc: Optional[int]
    tmask: Optional[str]
    fields: Dict[str, str]
    function_name: str
    instruction_text: str
    data_summary: str


@dataclass(frozen=True)
class ComponentSummary:
    event_count: int
    instruction_count: int
    first_cycle: Optional[int]
    last_cycle: Optional[int]
    stage_event_counts: Dict[str, int]
    stage_complete_count: int
    unique_pcs: int
    call_count: int
    ret_count: int
    unknown_pc_count: int


@dataclass(frozen=True)
class InstructionFlow:
    order_index: int
    uuid: int
    wid: Optional[int]
    pc: Optional[int]
    tmask: Optional[str]
    function_name: str
    instruction_text: str
    first_cycle: Optional[int]
    last_cycle: Optional[int]
    records_count: int
    stages: List[str]
    is_stage_complete: bool
    data_trace: List[str]
    events: List[AnalysedEvent]


@dataclass(frozen=True)
class ComponentAnalysis:
    key: Tuple[str, str, str]
    summary: ComponentSummary
    instructions: List[InstructionFlow]
    events: List[AnalysedEvent]
    call_trace: List[str]


@dataclass(frozen=True)
class AnalysisReport:
    trace_file: str
    dump_file: str
    components: List[ComponentAnalysis]


@dataclass(frozen=True)
class IntermediateFlowRow:
    component: str
    order: int
    uuid: int
    wid: str
    first_cycle: str
    last_cycle: str
    pc: str
    tmask: str
    function: str
    instruction: str
    stages: str
    stage_complete: str
    data_trace: str
