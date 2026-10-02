// Verify that Ghidra preserved every mapped file byte and zero-filled virtual tail.
// @category Halo2
import ghidra.app.script.GhidraScript;
import java.nio.file.*;

public class VerifyMapping extends GhidraScript {
    public void run() throws Exception {
        Path root = Paths.get(getScriptArgs()[0]);
        Files.deleteIfExists(root.resolve("analysis/mapping-verification.json"));
        byte[] xbe = Files.readAllBytes(root.resolve("default.xbe"));
        long total = 0;
        for (String row : Files.readAllLines(root.resolve("analysis/sections.tsv"))) {
            String[] f = row.split("\t");
            long va = Long.parseLong(f[1]);
            int size = Integer.parseInt(f[2]), offset = Integer.parseInt(f[3]);
            int raw = Integer.parseInt(f[4]), flags = Integer.parseInt(f[5]);
            var block = currentProgram.getMemory().getBlock(toAddr(va));
            if (block == null || block.getSize() != size || block.isExecute() != ((flags & 4) != 0) ||
                block.isWrite() != ((flags & 1) != 0)) throw new Exception("Mapping flags/size mismatch: " + f[0] +
                    "; actual=" + (block == null ? "missing" : block.getName() + " at " + block.getStart() + " size=" + block.getSize()));
            byte[] actual = new byte[size];
            currentProgram.getMemory().getBytes(toAddr(va), actual);
            for (int i = 0; i < size; i++) {
                byte expected = i < raw ? xbe[offset + i] : 0;
                if (actual[i] != expected) throw new Exception("Byte mismatch at " + Long.toHexString(va + i));
            }
            total += size;
        }
        if (getFunctionAt(toAddr(0x2d0aee)) == null) throw new Exception("Missing entry function");
        Files.writeString(root.resolve("analysis/mapping-verification.json"),
            "{\"passed\": true, \"mapped_bytes_checked\": " + total + "}\n");
        println("HALO2_MAPPING_VERIFIED bytes=" + total);
    }
}
