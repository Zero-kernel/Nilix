"""Focused generated-instruction, mapping, transition and RSP parser regressions."""
from dataclasses import replace
from pathlib import Path
import json
import re
import tempfile
import time
import unittest

from scripts.gates.qemu import mitigation_check as proof


def symbol(name, base, lines):
    labels, instructions = {}, []
    for line in lines:
        if line.endswith(":"):
            labels[line[:-1]] = base + len(instructions) * 4
        else:
            instructions.append(line)
    output = [f"{base:016x} <arch::fixture::{name}>:"]
    for index, text in enumerate(instructions):
        for label, address in labels.items():
            text = text.replace("@" + label, f"0x{address:x}")
        raw = "0f 22 d8" if text.startswith("mov cr3") else "90"
        output.append(f" {base + index * 4:x}: {raw} {text}")
    return "\n".join(output)


def fixture():
    return (Path(__file__).resolve().parents[1] / "fixtures/mitigation-v35-entry-disassembly.txt").read_text(encoding="utf-8")


def mapping(kernel=0x1000, user=0x2000):
    return (f"MITIGATION-MAP PASS kernel={kernel:x} user={user:x} " +
            " ".join(f"{key}={value}" for key, value in proof.MAP_FIELDS.items()) + " low_alias=true")


def transition(site, kernel=0x1000, user=0x2000):
    before_root, after_root = (user, kernel) if site["direction"] == "kernel" else (kernel, user)
    before = {"rip": site["address"], "cr3": before_root, "rax": 0, "rdx": 0, "cs": 8, "cpl": 0}
    before[site["register"]] = after_root
    after = {**before, "rip": site["address"] + site["length"], "cr3": after_root}
    return {**site, "before": before, "after": after, "thread": "1", "cpu": 0,
            "user_return": {**after, "cs": 0x33, "cpl": 3}}


def packet(payload):
    if isinstance(payload, str):
        payload = payload.encode()
    return b"$" + payload + b"#" + f"{sum(payload) & 255:02x}".encode()


class FakeSocket:
    def __init__(self, data):
        self.data, self.sent = data, bytearray()

    def settimeout(self, _timeout):
        pass

    def recv(self, count):
        value, self.data = self.data[:count], self.data[count:]
        return value

    def sendall(self, value):
        self.sent.extend(value)


class CPURegisterSocket(FakeSocket):
    """QEMU-like peer whose qC selection can differ from the stop event."""
    def __init__(self):
        super().__init__(b"")
        self.commands, self.selected_cpus = [], []
        self.general_thread, self.cpu = "p01.01", 0
        # CPU 0 matches the unrelated BSP shell RIP in the captured v37 run.
        # The other values are distinct synthetic proof-site register states.
        self.rips = [0xFFFFFFFF87628040, 0xFFFFFFFF8757BCFE, 0xFFFFFFFF8757C005]

    def sendall(self, value):
        super().sendall(value)
        if not value.startswith(b"$"):
            return
        command = value[1:value.rfind(b"#")].decode()
        self.commands.append(command)
        if command == "qC":
            response = packet("QC" + self.general_thread)
        elif command.startswith("Hg"):
            self.general_thread = command[2:]
            response = packet("OK")
        elif command.startswith("Hc"):
            response = packet("OK")
        elif command.startswith("qRcmd,"):
            monitor = bytes.fromhex(command.split(",", 1)[1]).decode()
            if monitor.startswith("cpu "):
                self.cpu = int(monitor.split()[1])
                self.selected_cpus.append(self.cpu)
                response = packet("OK")
            elif monitor == "info registers":
                registers = (f"RAX=1000 RDX=2000 RIP={self.rips[self.cpu]:x} "
                             "CR3=1000 CS=0008 CPL=0")
                response = packet("O" + registers.encode().hex()) + packet("OK")
            else:
                raise AssertionError("unexpected monitor command: " + monitor)
        else:
            raise AssertionError("unexpected RSP command: " + command)
        self.data += b"+" + response


class GeneratedProofTests(unittest.TestCase):
    def test_five_actual_generated_sites_and_control_flow_mutations(self):
        symbols = proof.parse_disassembly(fixture())
        scope = {}
        sites = proof.verify_generated(symbols, scope)
        self.assertEqual([site["address"] for site in sites],
                         [0xFFFFFFFF8011C1B3, 0xFFFFFFFF8011C34B, 0xFFFFFFFF8011BDDE,
                          0xFFFFFFFF8011BE1D, 0xFFFFFFFF8011C0E5])
        mutations = proof.verify_mutations(symbols)
        self.assertEqual(len(mutations), 34)
        self.assertEqual(len(mutations), len(set(mutations)))
        self.assertIn("syscall:normal-root-bypass", mutations)
        self.assertIn("syscall:nested-guard-target", mutations)
        self.assertIn("syscall:kernel-guard-target", mutations)
        self.assertEqual([site["register"] for site in sites], ["rax", "rdx", "rax", "rax", "rdx"])
        self.assertEqual(scope["manual_entry"], {"name": "enter_usermode", "linked": False, "executed": False})
        self.assertEqual(scope["syscall_paths"]["normal_return"], "0xffffffff8011c35d")
        self.assertEqual(scope["syscall_paths"]["nested_return"], "0xffffffff8011c399")
        self.assertIn("not dynamically exercised", scope["rejection_path_evidence"])

    def test_missing_body_is_unavailable(self):
        symbols = proof.parse_disassembly(fixture())
        symbols.pop(next(name for name in symbols if name.endswith("switch_to_user")))
        with self.assertRaises(proof.EvidenceUnavailable):
            proof.verify_generated(symbols)

    def test_duplicate_symbol_is_rejected(self):
        with self.assertRaises(proof.ProofFailure):
            proof.parse_disassembly(fixture() + "\n" + fixture())

    def test_unrelated_demangled_monomorphizations_do_not_hide_proof_bodies(self):
        repeated = "<alloc::raw_vec::RawVecInner>::finish_grow"
        text = fixture() + "\n" + symbol(repeated, 0x9000, ["ret"]) + "\n" + symbol(repeated, 0xa000, ["ret"])
        self.assertEqual(len(proof.verify_generated(proof.parse_disassembly(text))), 5)
        ambiguous = text + "\n" + symbol("syscall_entry_stub", 0xb000, ["ret"]).replace("arch::fixture::", "other::")
        with self.assertRaises(proof.EvidenceUnavailable):
            proof.verify_generated(proof.parse_disassembly(ambiguous))

    def test_wrong_gs_source_is_rejected(self):
        symbols = proof.parse_disassembly(fixture().replace("gs:[0x28]", "gs:[0x30]"))
        with self.assertRaises(proof.ProofFailure):
            proof.verify_generated(symbols)

    def test_timer_cs_source_and_branch_are_not_presence_only(self):
        for change in ("frame-offset", "rpl-mask", "kernel-skip"):
            symbols = proof.parse_disassembly(fixture())
            body = proof.body_for(symbols, "timer_interrupt_stub")
            test = next(i for i, item in enumerate(body) if item.mnemonic == "test" and item.op() == "al,0x3")
            if change == "frame-offset":
                body[test - 1] = replace(body[test - 1], operands="rax, qword ptr [rsp+120]")
            elif change == "rpl-mask":
                body[test] = replace(body[test], operands="al, 0")
            else:
                body[test + 1] = replace(body[test + 1], operands=hex(body[0].address))
            with self.subTest(change=change), self.assertRaises(proof.ProofFailure):
                proof.verify_generated(symbols)

    def test_target_clobber_is_rejected(self):
        symbols = proof.parse_disassembly(fixture())
        body = proof.body_for(symbols, "switch_to_user")
        load = next(i for i, item in enumerate(body) if item.op() == "rdx,gs:[0x28]")
        body[load + 1] = replace(body[load + 1], mnemonic="xor", operands="rdx, rdx")
        with self.assertRaises(proof.ProofFailure):
            proof.verify_generated(symbols)

    def test_same_root_comparison_must_use_source_and_opposite_root(self):
        for replacement in ("cmp rax, qword ptr gs:[32]", "cmp rdx, qword ptr gs:[40]"):
            symbols = proof.parse_disassembly(fixture())
            body = proof.body_for(symbols, "switch_to_user")
            index = next(i for i, item in enumerate(body) if item.mnemonic == "cmp" and item.op() == "rdx,gs:[0x20]")
            body[index] = replace(body[index], operands=replacement.split(" ", 1)[1])
            with self.assertRaises(proof.ProofFailure):
                proof.verify_generated(symbols)

    def test_equivalent_decimal_operands_and_carry_aliases(self):
        symbols = proof.parse_disassembly(fixture())
        for name in proof.STUBS:
            body = proof.body_for(symbols, name)
            for i, item in enumerate(body):
                # Keep branch addresses/symbol references intact. Normalize
                # register/memory immediates exactly as a disassembler may print.
                operands = item.operands if item.mnemonic.startswith(("j", "call")) else re.sub(
                    r"-?0x[0-9a-f]+", lambda match: str(int(match[0], 0)), item.operands)
                body[i] = replace(item, operands=operands, mnemonic="jc" if item.mnemonic == "jb" else item.mnemonic)
        self.assertEqual(len(proof.verify_generated(symbols)), 5)

    def test_unexpected_linked_manual_entry_is_unavailable(self):
        for name in ("enter_usermode", "enter_usermode::h123abc"):
            text = fixture() + "\n" + symbol(name, 0x9000, ["ret"])
            with self.subTest(name=name), self.assertRaises(proof.EvidenceUnavailable):
                proof.verify_generated(proof.parse_disassembly(text))

    def test_normal_address_checks_must_use_full_canonicality_and_low_half(self):
        for mnemonic, old, replacement in (("shl", "rbx,0x10", "rbx,15"),
                                           ("sar", "rbx,0x10", "rbx,15"),
                                           ("bt", "rdx,0x2f", "rdx,46")):
            symbols = proof.parse_disassembly(fixture())
            body = proof.body_for(symbols, "syscall_entry_stub")
            index = next(i for i, item in enumerate(body) if item.mnemonic == mnemonic and item.op() == old)
            body[index] = replace(body[index], operands=replacement)
            with self.subTest(mnemonic=mnemonic), self.assertRaises(proof.ProofFailure):
                proof.verify_generated(symbols)

    def test_unknown_normal_branch_and_returning_bad_target_are_rejected(self):
        for change in ("branch", "fatal-target"):
            symbols = proof.parse_disassembly(fixture())
            body = proof.body_for(symbols, "syscall_entry_stub")
            if change == "branch":
                body[10] = replace(body[10], mnemonic="jne", operands=hex(body[-1].address))
            else:
                index = next(i for i, item in enumerate(body) if "<syscall_bad_return>" in item.operands)
                body[index] = replace(body[index], operands="0x9990 <ordinary_return>")
            with self.subTest(change=change), self.assertRaises(proof.ProofFailure):
                proof.verify_generated(symbols)


class ObservationTests(unittest.TestCase):
    def test_runtime_relocation_requires_both_actual_symbol_addresses(self):
        anchor, release = 0xFFFFFFFF80101000, 0xFFFFFFFF80301000
        linked = proof.parse_anchor_symbols(
            f"{anchor:x} g F .text 00000001 {proof.ANCHOR}\n"
            f"{release:x} g O .bss 00000001 {proof.RELEASE}\n")
        sites = [{"address": anchor + 0x100, "name": "example"}]
        serial = f"MITIGATION-ANCHOR symbol={proof.ANCHOR} runtime=0x{anchor + 0x12000:x} release=0x{release + 0x12000:x}"
        relocated, evidence = proof.relocate_sites(serial, linked, sites)
        self.assertEqual(evidence["slide"], 0x12000)
        self.assertEqual(relocated[0]["address"], anchor + 0x12100)
        self.assertEqual(relocated[0]["linked_address"], anchor + 0x100)
        with self.assertRaises(proof.ProofFailure):
            proof.relocate_sites(serial.replace(f"{release + 0x12000:x}", f"{release + 0x13000:x}"), linked, sites)
        with self.assertRaises(proof.EvidenceUnavailable):
            proof.relocate_sites("no runtime observation", linked, sites)

    def test_relocation_symbols_cannot_be_missing_or_duplicated(self):
        entry = f"ffffffff80101000 g F .text 1 {proof.ANCHOR}\n"
        for symbols in (entry, entry + entry):
            with self.assertRaises(proof.EvidenceUnavailable):
                proof.parse_anchor_symbols(symbols)

    def test_mapping_is_partial_and_requires_every_field(self):
        parsed = proof.parse_mapping_records(mapping())
        self.assertEqual((parsed[0]["kernel"], parsed[0]["user"]), (0x1000, 0x2000))
        for text in [mapping().replace("full_isolation=false", "full_isolation=true"),
                     mapping().replace("stack_retained=true", ""),
                     mapping() + " kernel=1000", mapping(0x1000, 0x1000), mapping(0x1001, 0x2000)]:
            with self.assertRaises(proof.ProofFailure):
                proof.parse_mapping_records(text)

    def test_absent_mapping_is_not_a_pass(self):
        with self.assertRaises(proof.EvidenceUnavailable):
            proof.parse_mapping_records("boot complete")

    def test_register_parser(self):
        parsed = proof.parse_registers("RAX=00001000 RDX=00002000\nRIP=ffffffff80123456 CR3=00001003 CS =0008 CPL=0")
        self.assertEqual(parsed["cr3"], 0x1003)
        with self.assertRaises(proof.EvidenceUnavailable):
            proof.parse_registers("RIP=1000")

    def test_real_source_and_instruction_retirement_are_required(self):
        site = proof.verify_generated(proof.parse_disassembly(fixture()))[0]
        observed = transition(site)
        proof.verify_transition(site, observed["before"], observed["after"])
        for patch in [{"cr3": observed["before"]["cr3"]}, {"cr3": 0x3000}, {"rip": site["address"]}]:
            with self.assertRaises(proof.ProofFailure):
                proof.verify_transition(site, observed["before"], {**observed["after"], **patch})

    def test_all_sites_bind_to_actual_constructor_pairs(self):
        sites = proof.verify_generated(proof.parse_disassembly(fixture()))
        observations = [transition(site) for site in sites]
        proof.bind_transitions(sites, observations, proof.parse_mapping_records(mapping()))
        for records in [observations[:-1], observations + observations[:1],
                        [transition(site, 0x3000, 0x4000) for site in sites]]:
            with self.assertRaises(proof.ProofFailure):
                proof.bind_transitions(sites, records, proof.parse_mapping_records(mapping()))

    def test_four_cpus_and_actual_user_return_are_required(self):
        sites = proof.verify_generated(proof.parse_disassembly(fixture()))
        observed = [{**transition(site), "cpu": cpu, "thread": str(cpu + 1)}
                    for site in sites for cpu in range(4 if site["stub"] in proof.STUBS[:2] else 1)]
        mappings = proof.parse_mapping_records(mapping())
        proof.bind_transitions(sites, observed, mappings, 4)
        with self.assertRaises(proof.ProofFailure):
            proof.bind_transitions(sites, [item for item in observed if item["cpu"] != 3], mappings, 4)
        returned = next(item for item in observed if item["direction"] == "user")
        returned["user_return"]["cpl"] = 0
        with self.assertRaises(proof.ProofFailure):
            proof.bind_transitions(sites, observed, mappings, 4)

    def test_unexecuted_or_mismatched_build_cannot_qualify(self):
        record = {"target": "build-mitigation-probe", "status": 0,
                  "steps": [{"cwd": "/repo", "env": {}, "argv": ["build"]}] * 3,
                  "outputs": {"kernel": "a" * 64}}
        proof.verify_build_provenance(record, "a" * 64)
        for altered in [{**record, "status": 2}, {**record, "steps": []},
                        {**record, "outputs": {"kernel": "b" * 64}}, "provenance incomplete"]:
            with self.assertRaises(proof.ProofFailure):
                proof.verify_build_provenance(altered, "a" * 64)

    def test_workload_requires_each_fork_exec_and_pid1_completion(self):
        lines = ["MITIGATION-WORKLOAD BEGIN pid=1 cpus=4 forks=4 execs=4"]
        for cpu in range(4):
            for phase in ("fork", "exec"):
                for state in ("BEGIN", "PASS"):
                    fields = f"affinity={1 << cpu:x}" if state == "BEGIN" else "calls=32 elapsed_ms=250 checksum=123"
                    lines.append(f"MITIGATION-WORKER {state} phase={phase} cpu={cpu} pid={cpu + 2} {fields}")
            lines.append(f"MITIGATION-WAIT PASS cpu={cpu} pid={cpu + 2} raw_status=0 code=0")
        lines += ["MITIGATION-WORKLOAD PASS cpus=4 forks=4 execs=4", "Process 1 terminated with exit code 0"]
        serial = "\n".join(lines)
        proof.verify_workload(serial, 4)
        retry_line = "MITIGATION-WORKER RETRY phase=exec cpu=0 pid=2 attempt=1 errno=12"
        with_retry = serial.replace(
            "MITIGATION-WORKER PASS phase=exec cpu=0 pid=2 calls=32 elapsed_ms=250 checksum=123",
            retry_line + "\nMITIGATION-WORKER PASS phase=exec cpu=0 pid=2 calls=32 elapsed_ms=250 checksum=123")
        proof.verify_workload(with_retry, 4)
        for malformed_retry in (with_retry.replace("attempt=1", "attempt=2"),
                                with_retry.replace("errno=12", "errno=13"),
                                with_retry.replace("phase=exec cpu=0 pid=2 attempt=1", "phase=fork cpu=0 pid=2 attempt=1"),
                                with_retry + "\n" + retry_line):
            with self.assertRaises(proof.ProofFailure):
                proof.verify_workload(malformed_retry, 4)
        for broken in [serial.replace(lines[3], ""), serial.replace("exit code 0", "exit code 1"),
                       serial + "\n" + lines[1], serial + "\nMITIGATION-WORKLOAD FAIL",
                       serial.replace("pid=3", "pid=2").replace("pid=4", "pid=2").replace("pid=5", "pid=2"),
                       serial.replace("raw_status=0 code=0", "raw_status=256 code=1")]:
            with self.assertRaises(proof.ProofFailure):
                proof.verify_workload(broken, 4)


class StepRemote(proof.Remote):
    """Step protocol peer; retain the production stop/thread/register parser."""
    def __init__(self, snapshots, stops=None, opcodes=None):
        super().__init__(FakeSocket(b""), time.monotonic() + 1)
        self.snapshots, self.stops = snapshots, stops
        self.opcodes = opcodes or []
        self.steps, self.reads, self.register_reads = 0, 0, 0
        self.commands = []

    def command(self, command):
        self.commands.append(command)
        if command == "vCont?":
            return "vCont;c;C;s;S"
        if command == "s":
            # QEMU 6.2 legacy s resumes the VM: another vCPU may win its
            # breakpoint before the selected c_cpu executes its instruction.
            return "T05thread:p01.04;"
        if command == "vCont;s:p01.02":
            self.steps += 1
            if self.steps > len(self.snapshots):
                raise AssertionError("controller exceeded scripted step bound")
            return self.stops[self.steps - 1] if self.stops else "T05thread:p01.02;"
        if command.startswith(("Hg", "Hc")):
            return "OK"
        raise AssertionError("unexpected step command: " + command)

    def memory(self, address, length):
        self.reads += 1
        if self.reads <= len(self.opcodes):
            return self.opcodes[self.reads - 1]
        return bytes.fromhex("0f22d8")

    def monitor(self, command):
        if command.startswith("cpu "):
            return ""
        if command == "info registers":
            self.register_reads += 1
            return " ".join(f"{key.upper()}={value:x}"
                            for key, value in self.snapshots[self.steps - 1].items())
        raise AssertionError("unexpected monitor command: " + command)


class StepProgressTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(prefix="mitigation-step-test-")
        self.addCleanup(self.directory.cleanup)
        self.path = Path(self.directory.name) / "attempts.json"
        self.site = {"name": "timer_interrupt_stub:kernel", "address": 0xFFFFFFFF8012BD0E,
                     "length": 3, "register": "rax", "bytes": "0f22d8"}
        self.before = {"rip": self.site["address"], "cr3": 0xA40F000, "rax": 0xA49A000,
                       "rdx": 0, "cs": 8, "cpl": 0, "r15": 0, "cr4": 0x3006E8, "rfl": 6}
        self.after = {**self.before, "rip": self.site["address"] + 3, "cr3": 0xA49A000}
        self.attempts = []

    def step(self, remote):
        return proof.step_cr3_instruction(remote, self.site, self.before, "p01.02",
                                          self.attempts, self.path)

    def saved(self):
        saved = json.loads(self.path.read_text())
        self.assertEqual(saved, self.attempts)
        return saved

    def test_unchanged_stop_then_actual_retirement_is_recorded_separately(self):
        remote = StepRemote([self.before, self.after])
        self.assertEqual(self.step(remote), self.after)
        self.assertEqual(remote.steps, 2)
        self.assertEqual([row["outcome"] for row in self.saved()], ["no-progress", "retired"])
        self.assertTrue(all(row["opcode_before"] == row["opcode_after"] == "0f22d8"
                            for row in self.attempts))

    def test_two_unchanged_stops_may_precede_third_actual_retirement(self):
        remote = StepRemote([self.before, self.before, self.after])
        self.assertEqual(self.step(remote), self.after)
        self.assertEqual(remote.steps, 3)
        self.assertEqual([row["outcome"] for row in self.saved()],
                         ["no-progress", "no-progress", "retired"])

    def test_no_progress_bound_fails_and_persists_all_attempts(self):
        remote = StepRemote([self.before] * 3)
        with self.assertRaisesRegex(proof.ProofFailure, "no progress after three attempts"):
            self.step(remote)
        self.assertEqual(remote.steps, 3)
        self.assertEqual([row["outcome"] for row in self.saved()], ["no-progress"] * 3)
        self.assertIn("error", self.attempts[-1])

    def test_any_changed_register_or_missing_key_cannot_take_retry_path(self):
        changed = [{**self.before, key: self.before[key] ^ 1} for key in ("r15", "cr4", "rfl", "rax")]
        changed.append({key: value for key, value in self.before.items() if key != "r15"})
        for snapshot in changed:
            with self.subTest(snapshot=snapshot):
                self.attempts = []
                remote = StepRemote([snapshot])
                with self.assertRaisesRegex(proof.ProofFailure, "retire exactly"):
                    self.step(remote)
                self.assertEqual(remote.steps, 1)
                self.assertEqual(self.saved()[0]["outcome"], "rejected")

    def test_changed_opcode_before_during_or_between_attempts_fails(self):
        good, bad = bytes.fromhex("0f22d8"), bytes.fromhex("0f22da")
        for opcodes, steps in [([bad], 0), ([good, bad], 1), ([good, good, bad], 1),
                               ([good, good, good, bad], 2)]:
            with self.subTest(opcodes=opcodes):
                self.attempts = []
                remote = StepRemote([self.before, self.after], opcodes=opcodes)
                with self.assertRaisesRegex(proof.ProofFailure, "opcode changed"):
                    self.step(remote)
                self.assertEqual(remote.steps, steps)
                self.assertEqual(self.saved()[-1]["outcome"], "rejected")

    def test_changed_thread_signal_or_missing_identity_never_retries(self):
        for stop in ("T05thread:p01.03;", "T0bthread:p01.02;", "S05"):
            with self.subTest(stop=stop):
                self.attempts = []
                remote = StepRemote([self.before], stops=[stop])
                with self.assertRaises((proof.ProofFailure, proof.EvidenceUnavailable)):
                    self.step(remote)
                self.assertEqual(remote.steps, 1)
                self.assertEqual(remote.register_reads, 0)
                self.assertEqual(self.saved()[0]["stop"], stop)
                self.assertEqual(self.attempts[0]["outcome"], "rejected")

    def test_retired_rip_with_wrong_root_is_still_a_failure(self):
        remote = StepRemote([{**self.after, "cr3": self.before["cr3"]}])
        with self.assertRaisesRegex(proof.ProofFailure, "actual source-register"):
            self.step(remote)
        self.assertEqual(remote.steps, 1)
        self.assertEqual(self.saved()[0]["outcome"], "rejected")

    def test_runtime_clock_contract_retains_four_logical_cpus(self):
        command = proof.runtime_qemu_command("qemu", Path("firmware.fd"), Path("guest"),
                                             Path("output"), Path("gdb.sock"), 4, "qemu64,+smep,+smap")
        self.assertEqual(command.count("-accel"), 1)
        self.assertEqual(command[command.index("-accel") + 1], "tcg,thread=single")
        self.assertEqual(command.count("-icount"), 1)
        self.assertEqual(command[command.index("-icount") + 1], "shift=3,align=off,sleep=off")
        self.assertEqual(command[command.index("-smp") + 1], "4")
        self.assertEqual(command[command.index("-cpu") + 1], "qemu64,+smep,+smap")
        self.assertIn("-S", command)

    def test_exact_vcont_step_excludes_peer_that_wins_after_legacy_step(self):
        epilogue = {**self.after, "rip": self.after["rip"] + 3}
        remote = StepRemote([self.after, epilogue])
        remote.ok("Hcp01.02")
        legacy_stop = remote.command("s")
        self.assertEqual(proof.parse_stop_thread(legacy_stop), "p01.04")
        self.assertEqual(remote.steps, 0)
        with self.assertRaisesRegex(proof.ProofFailure, "changed QEMU CPU thread"):
            remote.registers(legacy_stop, expected_thread="p01.02")

        # The CR3 helper and subsequent return microstep use the same scoped
        # command. Unspecified peers stay stopped; the equality guard remains.
        self.assertEqual(self.step(remote), self.after)
        stop = remote.step_thread("p01.02")
        self.assertEqual(remote.registers(stop, expected_thread="p01.02")[1], epilogue)
        self.assertEqual(remote.commands.count("vCont?"), 1)
        self.assertEqual(remote.commands.count("vCont;s:p01.02"), 2)
        self.assertEqual(self.saved()[0]["command"], "vCont;s:p01.02")

    def test_rejected_vcont_step_is_persisted_without_legacy_fallback(self):
        peer = FakeSocket(packet("0f22d8") + packet("vCont;c;C;s;S") + packet("E22"))
        remote = proof.Remote(peer, time.monotonic() + 1)
        with self.assertRaises(proof.EvidenceUnavailable):
            self.step(remote)
        self.assertEqual(len(self.saved()), 1)
        self.assertEqual(self.attempts[0]["stop"], "E22")
        self.assertEqual(self.attempts[0]["outcome"], "rejected")
        self.assertNotIn(b"$s#", peer.sent)


class RemoteTests(unittest.TestCase):
    def test_coalesced_packets_and_fragmented_reads_preserve_framing(self):
        class BufferedSocket(FakeSocket):
            def __init__(self, data, chunk):
                super().__init__(data)
                self.chunk = chunk
                self.reads = 0

            def recv(self, length):
                self.reads += 1
                result = self.data[:min(length, self.chunk)]
                self.data = self.data[len(result):]
                return bytes(result)

        payload = b"+" + packet("O" + b"RIP=1000 ".hex()) + packet("OK") + packet("0f22d8")
        for chunk in (1, 3, len(payload)):
            with self.subTest(chunk=chunk):
                peer = BufferedSocket(payload, chunk)
                remote = proof.Remote(peer, time.monotonic() + 2)
                self.assertEqual(remote.monitor("info registers"), "RIP=1000 ")
                self.assertEqual(remote.memory(0x1000, 3), bytes.fromhex("0f22d8"))
                if chunk == len(payload):
                    self.assertEqual(peer.reads, 1)

    def test_buffered_reply_does_not_bypass_deadline_or_checksum(self):
        remote = proof.Remote(FakeSocket(b""), time.monotonic() - 1)
        remote.buffer = packet("OK")
        with self.assertRaisesRegex(proof.EvidenceUnavailable, "deadline"):
            remote.receive()
        remote.deadline = time.monotonic() + 2
        remote.buffer = b"$OK#00"
        with self.assertRaisesRegex(proof.EvidenceUnavailable, "checksum"):
            remote.receive()

    def remote(self, data):
        return proof.Remote(FakeSocket(data), time.monotonic() + 1)

    def test_acknowledged_reply(self):
        remote = self.remote(b"+" + packet("OK"))
        remote.ok("Z1,1000,1")
        self.assertTrue(remote.connection.sent.endswith(b"+"))
        self.assertIn(b"$Z1,1000,1#", remote.connection.sent)

    def test_monitor_console_fragments(self):
        remote = self.remote(packet("O" + b"RIP=1000 ".hex()) + packet("O" + b"CR3=2000".hex()) + packet("OK"))
        self.assertEqual(remote.monitor("info registers"), "RIP=1000 CR3=2000")

    def test_checksum_and_unsupported_breakpoint_are_blocked(self):
        with self.assertRaises(proof.EvidenceUnavailable):
            self.remote(b"$OK#00").receive()
        with self.assertRaises(proof.EvidenceUnavailable):
            self.remote(packet("E22")).ok("Z1,1000,1")

    def test_escaped_and_run_length_payload(self):
        self.assertEqual(self.remote(packet(b"a* " + b"}" + bytes([ord("#") ^ 32]))).receive(), "aaaa#")

    def test_connection_close_is_unavailable(self):
        with self.assertRaises(proof.EvidenceUnavailable):
            self.remote(b"").receive()

    def test_memory_and_interrupt_evidence(self):
        remote = self.remote(packet("0f22d8") + packet("T02thread:1;"))
        self.assertEqual(remote.memory(0x1000, 3), b"\x0f\x22\xd8")
        self.assertTrue(remote.interrupt().startswith("T02"))
        self.assertIn(b"\x03", remote.connection.sent)
        for payload in ("E14", "0f22", "0f22d8ff"):
            with self.assertRaises(proof.EvidenceUnavailable):
                self.remote(packet(payload)).memory(0x1000, 3)

    def test_stop_event_selects_cpu_even_when_qc_still_selects_bsp(self):
        peer = CPURegisterSocket()
        remote = proof.Remote(peer, time.monotonic() + 1)
        self.assertEqual(remote.command("qC"), "QCp01.01")
        peer.commands.clear()
        thread, registers = remote.registers("T05thread:p01.03;")
        self.assertEqual(thread, "p01.03")
        self.assertEqual(registers["rip"], peer.rips[2])
        self.assertEqual(peer.selected_cpus, [2])
        self.assertEqual(peer.commands, ["Hgp01.03", "Hcp01.03",
                                        "qRcmd," + b"cpu 2".hex(),
                                        "qRcmd," + b"info registers".hex()])

    def test_consecutive_stops_use_each_events_thread(self):
        peer = CPURegisterSocket()
        remote = proof.Remote(peer, time.monotonic() + 1)
        remote.registers("T05thread:p01.03;")
        self.assertEqual(remote.command("qC"), "QCp01.03")
        thread, registers = remote.registers("T05thread:p01.02;")
        self.assertEqual(thread, "p01.02")
        self.assertEqual(registers["rip"], peer.rips[1])
        self.assertEqual(peer.selected_cpus, [2, 1])

    def test_single_step_rejects_changed_thread_before_register_selection(self):
        peer = CPURegisterSocket()
        remote = proof.Remote(peer, time.monotonic() + 1)
        remote.registers("T05thread:p01.03;", expected_thread="p01.03")
        before = list(peer.commands)
        with self.assertRaises(proof.ProofFailure):
            remote.registers("T05thread:p01.02;", expected_thread="p01.03")
        self.assertEqual(peer.commands, before)

    def test_missing_malformed_and_ambiguous_stop_threads_are_unavailable(self):
        for stop in ("T05", "S05", "T05thread:;", "T05thread:p01.03",
                     "T05thread:p01.gg;", "T05thread:p01.00;", "T05thread:p00.01;",
                     "T05thread:0;", "T05thread:-1;", "T05thread:p01.03;;",
                     "T05thread:p01.03;thread:p01.01;", "T05thread:3;thread:3;",
                     "T05thread:p01.03;malformed;", "T05thread:p01.03;\n"):
            with self.subTest(stop=stop):
                remote = self.remote(b"")
                with self.assertRaises(proof.EvidenceUnavailable):
                    remote.registers(stop)
                self.assertFalse(remote.connection.sent)
        self.assertEqual(proof.parse_stop_thread("T05hwbreak:;thread:3;"), "3")

    def test_non_sigtrap_proof_stops_cannot_pass(self):
        for signal in ("00", "02", "0b", "ff"):
            remote = self.remote(b"")
            with self.assertRaises(proof.ProofFailure):
                remote.registers(f"T{signal}thread:p01.03;")
            self.assertFalse(remote.connection.sent)

    def test_thread_steps_query_capability_once_and_emit_only_explicit_actions(self):
        remote = self.remote(packet("vCont;c;C;s;S") + packet("T05thread:p01.03;") +
                             packet("T05thread:p01.02;"))
        self.assertEqual(remote.step_thread("p01.03"), "T05thread:p01.03;")
        self.assertEqual(remote.step_thread("p01.02"), "T05thread:p01.02;")
        self.assertEqual([row["send"] for row in remote.transcript if "send" in row],
                         ["vCont?", "vCont;s:p01.03", "vCont;s:p01.02"])

    def test_missing_or_malformed_vcont_step_capability_fails_before_resume(self):
        for response in ("", "E22", "vContSupported+", "vCont;c;C;S", "vCont;s;", "vCont;s:p01.02"):
            with self.subTest(response=response):
                remote = self.remote(packet(response))
                with self.assertRaises(proof.EvidenceUnavailable):
                    remote.step_thread("p01.02")
                self.assertEqual([row["send"] for row in remote.transcript if "send" in row], ["vCont?"])
                self.assertFalse(remote.thread_step_supported)

    def test_wildcard_or_injected_step_thread_is_rejected_before_any_command(self):
        for thread in ("-1", "0", "p01.-1", "p01.00", "p00.01", "p01.02;c", "p01.02;s:p01.03"):
            with self.subTest(thread=thread):
                remote = self.remote(b"")
                with self.assertRaises(proof.EvidenceUnavailable):
                    remote.step_thread(thread)
                self.assertFalse(remote.connection.sent)


if __name__ == "__main__":
    unittest.main()
