// Seed functions from reviewed indirect-dispatch evidence, not arbitrary data scans.
// @category Halo2
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.AddressSet;
import java.nio.file.*;

public class DiscoverEngine extends GhidraScript {
    public void run() throws Exception {
        Path out = Paths.get(getScriptArgs()[0]).resolve("analysis");
        Files.deleteIfExists(out.resolve("engine-discovery.json"));
        int created = 0, existing = 0, conflicts = 0;
        try (var report = Files.newBufferedWriter(out.resolve("engine-discovery.tsv"))) {
            report.write("address\tstatus\tevidence\n");
            for (String row : Files.readAllLines(out.resolve("engine-seeds.tsv"))) {
                String[] fields = row.split("\t",2);
                var address = toAddr(Long.parseLong(fields[0],16));
                String status;
                if (getFunctionAt(address) != null) { status = "existing"; existing++; }
                else if (getFunctionContaining(address) != null) {
                    var owner = getFunctionContaining(address);
                    long target = address.getOffset();
                    long branch = target == 0x8dd70 ? 0x8dd67 : target == 0x20a750 ? 0x20a743 : -1;
                    long expectedOwner = target == 0x8dd70 ? 0x8d9f0 : 0x20a700;
                    var ins = branch < 0 ? null : getInstructionAt(toAddr(branch));
                    // These two tail jumps were reviewed in the original x86.
                    // Both targets independently occur in the lifecycle table.
                    if (ins != null && owner.getEntryPoint().getOffset() == expectedOwner &&
                        ins.getFlowType().isJump() && !ins.getFlowType().isConditional() &&
                        ins.getFlows().length == 1 && ins.getFlows()[0].equals(address)) {
                        var originalBody = owner.getBody();
                        // Keep the prefix, rather than the target and subsequent addresses.
                        var prefix = new AddressSet(originalBody);
                        prefix.delete(address, originalBody.getMaxAddress());
                        owner.setBody(prefix);
                        var f = createFunction(address,null);
                        if (f == null) {
                            owner.setBody(originalBody);
                            status = "split_failed"; conflicts++;
                        } else {
                            f.setComment("Independent lifecycle callback, tail-called at " + toAddr(branch) +
                                ". Boundary split verified against x86. " + fields[1]);
                            Files.deleteIfExists(out.resolve("decompiled/"+owner.getEntryPoint()+".c"));
                            status = "reviewed_tail_split"; created++;
                        }
                    } else {
                        status = "conflict_with_"+owner.getEntryPoint(); conflicts++;
                    }
                } else {
                    disassemble(address);
                    var f = createFunction(address, null);
                    if (f == null) { status = "failed"; conflicts++; }
                    else {
                        f.setComment("Function seed evidence: " + fields[1] + ". Signature not yet reviewed.");
                        status = "created"; created++;
                    }
                }
                report.write(fields[0]+"\t"+status+"\t"+fields[1]+"\n");
            }
        }
        Files.writeString(out.resolve("engine-discovery.json"),"{\"created\":"+created+
            ",\"existing\":"+existing+",\"unresolved\":"+conflicts+"}\n");
        println("HALO2_ENGINE_DISCOVERY created="+created+" existing="+existing+" unresolved="+conflicts);
    }
}
