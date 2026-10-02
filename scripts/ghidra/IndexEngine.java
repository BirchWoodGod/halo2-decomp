// Index string-reference evidence; these are candidates, not verified function names.
// @category Halo2
import ghidra.app.script.GhidraScript;
import java.nio.file.*;

public class IndexEngine extends GhidraScript {
    public void run() throws Exception {
        Path out = Paths.get(getScriptArgs()[0]).resolve("analysis");
        int count = 0;
        try (var writer = Files.newBufferedWriter(out.resolve("engine-candidates.tsv"))) {
            writer.write("category\tfunction\tname\treference\tstring_address\tstring\n");
            for (String row : Files.readAllLines(out.resolve("anchors.tsv"))) {
                String[] fields = row.split("\t", 3);
                var address = toAddr(Long.parseLong(fields[0]));
                var refs = currentProgram.getReferenceManager().getReferencesTo(address);
                while (refs.hasNext()) {
                    var ref = refs.next();
                    var function = getFunctionContaining(ref.getFromAddress());
                    if (function == null) continue;
                    var block = currentProgram.getMemory().getBlock(function.getEntryPoint());
                    if (block == null || !block.getName().equals("00_.text")) continue;
                    writer.write(fields[1] + "\t" + function.getEntryPoint() + "\t" + function.getName() +
                        "\t" + ref.getFromAddress() + "\t" + address + "\t" + fields[2] + "\n");
                    count++;
                }
            }
        }
        println("HALO2_ENGINE_INDEX references=" + count);
    }
}
