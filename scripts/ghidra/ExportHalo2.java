// Export analysis artifacts. Existing successful C exports are retained on resume.
// @category Halo2
import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.DecompInterface;
import ghidra.program.model.listing.Function;
import java.nio.file.*;
import java.io.*;
import java.nio.charset.StandardCharsets;

public class ExportHalo2 extends GhidraScript {
    public void run() throws Exception {
        Path out = Paths.get(getScriptArgs()[0]).resolve("analysis");
        if (!Files.exists(out.resolve("mapping-verification.json")))
            throw new IOException("Run VerifyMapping successfully before exporting");
        Path cdir = out.resolve("decompiled");
        Files.createDirectories(cdir);
        DecompInterface decomp = new DecompInterface();
        if (!decomp.openProgram(currentProgram)) throw new IOException(decomp.getLastMessage());
        int ok = 0, failed = 0, count = 0, excluded = 0;
        try (var index = Files.newBufferedWriter(out.resolve("functions.tsv"));
             var errors = Files.newBufferedWriter(out.resolve("decompiler-errors.tsv"));
             var calls = Files.newBufferedWriter(out.resolve("calls.tsv"));
             var asm = Files.newBufferedWriter(out.resolve("disassembly.asm"))) {
            index.write("address\tname\tbytes\tstatus\n");
            calls.write("caller\tcallee\n");
            var iterator = currentProgram.getFunctionManager().getFunctions(true);
            while (iterator.hasNext() && !monitor.isCancelled()) {
                Function f = iterator.next();
                if (f.isExternal()) continue;
                var block = currentProgram.getMemory().getBlock(f.getEntryPoint());
                if (block == null || !block.getName().equals("00_.text")) { excluded++; continue; }
                String address = f.getEntryPoint().toString();
                Path dest = cdir.resolve(address + ".c");
                String status;
                if (Files.exists(dest)) { ok++; status = "existing"; }
                else {
                    var result = decomp.decompileFunction(f, 10, monitor);
                    if (result.decompileCompleted() && result.getDecompiledFunction() != null) {
                        Files.writeString(dest, "/* Ghidra pseudocode; unreviewed, not buildable source.\n" +
                            " * XBE address: " + address + " */\n\n" + result.getDecompiledFunction().getC());
                        ok++; status = "exported";
                    } else {
                        failed++; status = "failed";
                        errors.write(address + "\t" + result.getErrorMessage().replace('\n', ' ') + "\n");
                    }
                }
                index.write(address + "\t" + f.getName() + "\t" + f.getBody().getNumAddresses() + "\t" + status + "\n");
                for (Function callee : f.getCalledFunctions(monitor))
                    calls.write(address + "\t" + callee.getEntryPoint() + "\n");
                asm.write("\n; " + f.getName() + " @ " + address + "\n");
                var instructions = currentProgram.getListing().getInstructions(f.getBody(), true);
                while (instructions.hasNext()) {
                    var ins = instructions.next();
                    asm.write(ins.getAddress() + "  " + ins + "\n");
                }
                if (++count % 500 == 0) println("HALO2_EXPORT functions=" + count + " successes=" + ok + " failures=" + failed);
            }
        } finally { decomp.dispose(); }
        Files.writeString(out.resolve("export-summary.json"),
            "{\n  \"functions\": " + count + ",\n  \"decompiled\": " + ok +
            ",\n  \"failed\": " + failed + ",\n  \"excluded_non_text\": " + excluded +
            ",\n  \"cancelled\": " + monitor.isCancelled() + "\n}\n");
        println("HALO2_EXPORT_COMPLETE functions=" + count + " successes=" + ok + " failures=" + failed);
    }
}
