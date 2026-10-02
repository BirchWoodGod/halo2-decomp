// Map the original XBE without modifying its bytes; preserve Xbox virtual addresses.
// @category Halo2
import ghidra.app.script.GhidraScript;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.data.DWordDataType;
import java.nio.file.*;
import java.io.ByteArrayInputStream;

public class LoadHalo2 extends GhidraScript {
    public void run() throws Exception {
        Path root = Paths.get(getScriptArgs()[0]);
        byte[] xbe = Files.readAllBytes(root.resolve("default.xbe"));
        var memory = currentProgram.getMemory();
        for (MemoryBlock block : memory.getBlocks()) memory.removeBlock(block, monitor);
        currentProgram.setImageBase(toAddr(0x10000), true);
        for (String row : Files.readAllLines(root.resolve("analysis/sections.tsv"))) {
            String[] f = row.split("\t");
            long va = Long.parseLong(f[1]);
            int size = Integer.parseInt(f[2]), offset = Integer.parseInt(f[3]);
            int raw = Integer.parseInt(f[4]), flags = Integer.parseInt(f[5]);
            byte[] mapped = new byte[size];
            System.arraycopy(xbe, offset, mapped, 0, raw);
            MemoryBlock block = memory.createInitializedBlock(f[0], toAddr(va),
                new ByteArrayInputStream(mapped), size, monitor, false);
            block.setRead(true);
            block.setWrite((flags & 1) != 0);
            block.setExecute((flags & 4) != 0);
            block.setComment("XBE raw offset " + offset + ", raw length " + raw +
                "; zero-filled virtual tail. Static view includes all sections.");
        }
        for (String row : Files.readAllLines(root.resolve("analysis/imports.tsv"))) {
            String[] f = row.split("\t");
            var address = toAddr(Long.parseLong(f[0]));
            createData(address, DWordDataType.dataType);
            createLabel(address, "__imp_" + f[2], true);
            setEOLComment(address, "xboxkrnl.exe ordinal " + f[1] + "; unresolved at rest");
            currentProgram.getReferenceManager().addExternalReference(address, "xboxkrnl.exe",
                f[2], null, SourceType.IMPORTED, 0, RefType.DATA);
        }
        long entry = Long.parseLong(Files.readString(root.resolve("analysis/entry.txt")).trim());
        var address = toAddr(entry);
        currentProgram.getSymbolTable().addExternalEntryPoint(address);
        disassemble(address);
        createFunction(address, "xbe_entry");
        println("HALO2_MAPPING_COMPLETE entry=" + address);
    }
}
