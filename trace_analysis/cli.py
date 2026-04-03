import argparse
import os
import sys

from .analyser import TraceAnalyser
from .comparator import render_intermediate_comparison
from .dump_db import DumpDatabase
from .renderer import AnalysisRenderer


def discover_dump_file(trace_file, explicit_dump_file):
    if explicit_dump_file:
        return explicit_dump_file

    trace_dir = os.path.dirname(os.path.abspath(trace_file))
    candidates = [
        os.path.join(trace_dir, "kernel.dump"),
        os.path.join(trace_dir, "tests", "regression", "mstress", "kernel.dump"),
        os.path.join(
            os.getcwd(), "build", "tests", "regression", "mstress", "kernel.dump"
        ),
        os.path.join(os.getcwd(), "kernel.dump"),
    ]

    for candidate in candidates:
        if os.path.isfile(candidate):
            return candidate
    return None


def parse_args(argv):
    parser = argparse.ArgumentParser(
        description="analyse Vortex execution trace and annotate PCs with disassembly and functions."
    )
    parser.add_argument(
        "trace_file",
        nargs="?",
        help="Execution trace log file (positional alternative to -i/--input).",
    )
    parser.add_argument(
        "dump_file",
        nargs="?",
        help="Disassembly dump file (positional alternative to -k/--dump-file).",
    )
    parser.add_argument(
        "-i",
        "--input",
        dest="input_trace_file",
        default=None,
        help="Execution trace log file (e.g., build/run.log).",
    )
    parser.add_argument(
        "-k",
        "--dump-file",
        dest="input_dump_file",
        default=None,
        help="RISC-V disassembly dump file (e.g., build/tests/regression/demo/kernel.dump).",
    )
    parser.add_argument(
        "-o",
        "--output",
        default=None,
        help="Output analysis file path. Default: <trace_file>.analysis",
    )
    parser.add_argument(
        "--intermediate-output",
        default=None,
        help=(
            "Path for comparison-friendly TSV output. "
            "Default: <analysis_file>.intermediate.tsv"
        ),
    )
    parser.add_argument(
        "--compare-tsv",
        default=None,
        help=(
            "Compare generated intermediate TSV against another intermediate TSV file, "
            "and print first divergence per component."
        ),
    )
    parser.add_argument(
        "--compare-output",
        default=None,
        help=(
            "Optional path to write comparison text report. "
            "Default: <intermediate_file>.compare.txt"
        ),
    )
    parser.add_argument(
        "--compare-label-a",
        default="current",
        help="Label for generated intermediate TSV in comparison report.",
    )
    parser.add_argument(
        "--compare-label-b",
        default="reference",
        help="Label for --compare-tsv input in comparison report.",
    )
    return parser.parse_args(argv)


def write_text_file(path: str, content: str) -> None:
    with open(path, "w") as f:
        f.write(content)


def main() -> None:
    args = parse_args(sys.argv[1:])

    trace_file = args.input_trace_file if args.input_trace_file else args.trace_file
    if trace_file is None:
        print("Error: missing trace file. Provide it via -i/--input or positional argument.")
        sys.exit(1)

    explicit_dump_file = args.input_dump_file if args.input_dump_file else args.dump_file
    dump_file = discover_dump_file(trace_file, explicit_dump_file)
    if dump_file is None:
        print(
            "Error: could not locate kernel dump file. Please pass it explicitly via -k/--dump-file or as the second positional argument."
        )
        sys.exit(1)

    if not os.path.isfile(trace_file):
        print(f"Error: trace file not found: {trace_file}")
        sys.exit(1)

    dump_db = DumpDatabase.from_file(dump_file)
    if not dump_db.instructions:
        print(f"Error: no disassembly instructions parsed from: {dump_file}")
        sys.exit(1)

    analyser = TraceAnalyser(dump_db)
    report = analyser.analyse_trace(trace_file=trace_file, dump_file=dump_file)
    renderer = AnalysisRenderer()
    output_text = renderer.render(report)

    analysis_file = args.output if args.output else trace_file + ".analysis"
    write_text_file(analysis_file, output_text)

    intermediate_text = renderer.render_intermediate_tsv(report)
    intermediate_file = (
        args.intermediate_output
        if args.intermediate_output
        else analysis_file + ".intermediate.tsv"
    )
    write_text_file(intermediate_file, intermediate_text)

    print(f"Analysis written to: {analysis_file}")
    print(f"Intermediate TSV written to: {intermediate_file}")

    if args.compare_tsv:
        if not os.path.isfile(args.compare_tsv):
            print(f"Error: compare TSV not found: {args.compare_tsv}")
            sys.exit(1)

        comparison_text = render_intermediate_comparison(
            tsv_a=intermediate_file,
            tsv_b=args.compare_tsv,
            label_a=args.compare_label_a,
            label_b=args.compare_label_b,
        )
        comparison_file = (
            args.compare_output
            if args.compare_output
            else intermediate_file + ".compare.txt"
        )
        write_text_file(comparison_file, comparison_text)
        print(comparison_text)
        print(f"Comparison report written to: {comparison_file}")
