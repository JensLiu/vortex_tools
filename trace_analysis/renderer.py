import sys
from typing import List, Optional, Tuple

from .models import AnalysisReport


class AnalysisRenderer:
    @staticmethod
    def _component_name(key: Tuple[str, str, str]) -> str:
        cluster, socket, core = key
        return f"{cluster}-{socket}-{core}"

    @staticmethod
    def _cycle_text(cycle: Optional[int]) -> str:
        return str(cycle) if cycle is not None else "?"

    @staticmethod
    def _pc_text(pc: Optional[int]) -> str:
        return hex(pc) if pc is not None else "<unknown-pc>"

    @staticmethod
    def render_intermediate_tsv(report: AnalysisReport) -> str:
        lines: List[str] = []
        lines.append(
            "kind\tcomponent\torder\tuuid\twid\tfirst_cycle\tlast_cycle\tpc\ttmask\tfunction\tinstruction\tstages\tstage_complete\tdata_trace"
        )

        for component in report.components:
            component_name = AnalysisRenderer._component_name(component.key)
            for flow in component.instructions:
                wid_text = str(flow.wid) if flow.wid is not None else ""
                first_cycle = (
                    str(flow.first_cycle) if flow.first_cycle is not None else ""
                )
                last_cycle = str(flow.last_cycle) if flow.last_cycle is not None else ""
                pc_text = hex(flow.pc) if flow.pc is not None else ""
                tmask_text = flow.tmask if flow.tmask is not None else ""
                stages = ">".join(flow.stages)
                data_trace = " || ".join(flow.data_trace).replace("\t", " ")
                lines.append(
                    "\t".join(
                        [
                            "flow",
                            component_name,
                            str(flow.order_index),
                            str(flow.uuid),
                            wid_text,
                            first_cycle,
                            last_cycle,
                            pc_text,
                            tmask_text,
                            flow.function_name,
                            flow.instruction_text,
                            stages,
                            "1" if flow.is_stage_complete else "0",
                            data_trace,
                        ]
                    )
                )

                for ev in flow.events:
                    ev_cycle = str(ev.cycle) if ev.cycle is not None else ""
                    ev_wid = str(ev.wid) if ev.wid is not None else ""
                    ev_pc = hex(ev.pc) if ev.pc is not None else ""
                    ev_tmask = ev.tmask if ev.tmask is not None else ""
                    ev_data = ev.data_summary.replace("\t", " ")
                    lines.append(
                        "\t".join(
                            [
                                "event",
                                component_name,
                                str(ev.line_no),
                                str(ev.uuid),
                                ev_wid,
                                ev_cycle,
                                "",
                                ev_pc,
                                ev_tmask,
                                ev.function_name,
                                ev.stage,
                                "",
                                "",
                                ev_data,
                            ]
                        )
                    )

        return "\n".join(lines)

    def render(self, report: AnalysisReport) -> str:
        lines: List[str] = []
        lines.append(f"# Trace file: {report.trace_file}")
        lines.append(f"# Dump file: {report.dump_file}")
        lines.append("")

        lines.append("Call Trace Summary (commit-stage calls/rets):")
        if not report.components:
            lines.append("  (no records found)")
        else:
            for component in report.components:
                name = self._component_name(component.key)
                lines.append(f"  {name}:")
                if component.call_trace:
                    lines.extend(component.call_trace)
                else:
                    lines.append("    (no call/ret instructions observed)")
        lines.append("")

        lines.append("Instruction Data-Flow Summary (UUID-correlated):")
        if not report.components:
            lines.append("  (no instruction flows)")
        else:
            for component in report.components:
                name = self._component_name(component.key)
                lines.append(f"  {name}:")
                s = component.summary
                lines.append(
                    f"    events={s.event_count}, instructions={s.instruction_count}, stage-complete={s.stage_complete_count}, "
                    f"cycles={self._cycle_text(s.first_cycle)}..{self._cycle_text(s.last_cycle)}, unique-pcs={s.unique_pcs}, "
                    f"unknown-pcs={s.unknown_pc_count}"
                )
                if s.stage_event_counts:
                    stage_counts_text = ", ".join(
                        f"{stage}:{count}"
                        for stage, count in sorted(s.stage_event_counts.items())
                    )
                    lines.append(f"    stage-counts: {stage_counts_text}")

                for flow in component.instructions:
                    lines.append(
                        f"    [#{flow.order_index:05d}] uuid=#{flow.uuid} cycle={self._cycle_text(flow.first_cycle)}..{self._cycle_text(flow.last_cycle)} "
                        f"wid={flow.wid if flow.wid is not None else '?'} pc={self._pc_text(flow.pc)} tmask={flow.tmask if flow.tmask is not None else '?'} "
                        f"fn={flow.function_name} instr={flow.instruction_text}"
                    )
                    lines.append(
                        f"      stages: {' > '.join(flow.stages) if flow.stages else '<none>'}"
                    )
                    lines.append(
                        f"      stage-complete: {'yes' if flow.is_stage_complete else 'no'}"
                    )
                    if flow.data_trace:
                        lines.append("      data-trace:")
                        for entry in flow.data_trace:
                            lines.append(f"        - {entry}")
                    else:
                        lines.append("      data-trace: (no payload fields captured)")
                lines.append("")

        lines.append("Raw UUID Events:")
        if not report.components:
            lines.append("  (no events)")
        else:
            for component in report.components:
                name = self._component_name(component.key)
                lines.append(f"  {name}:")
                for event in sorted(
                    component.events,
                    key=lambda e: (
                        e.cycle if e.cycle is not None else sys.maxsize,
                        e.line_no,
                    ),
                ):
                    cycle_text = self._cycle_text(event.cycle)
                    data_suffix = f" | {event.data_summary}" if event.data_summary else ""
                    lines.append(
                        f"    [line={event.line_no:07d}] cycle={cycle_text} uuid=#{event.uuid} stage={event.stage} "
                        f"wid={event.wid if event.wid is not None else '?'} pc={self._pc_text(event.pc)} "
                        f"fn={event.function_name}{data_suffix}"
                    )
                lines.append("")

        return "\n".join(lines)
