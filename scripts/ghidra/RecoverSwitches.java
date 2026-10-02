// Recover two unguarded enum dispatches whose automatic analysis ran into data.
// @category Halo2
import ghidra.app.script.GhidraScript;
import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.*;
import ghidra.program.model.pcode.JumpTable;
import ghidra.program.model.symbol.*;
import java.nio.file.*;
import java.util.*;

public class RecoverSwitches extends GhidraScript {
    public void run() throws Exception {
        Path out = Paths.get(getScriptArgs()[0]).resolve("analysis");
        Files.deleteIfExists(out.resolve("switch-recovery.json"));
        // function, indirect jump, pointer table, then exact reviewed entries.
        long[][] switches = {
            {0x68c00,0x68c19,0x68da8,0x68c20,0x68c32,0x68c29,0x68c44,0x68c3b},
            {0x1e5af0,0x1e5afa,0x1e5b30,0x1e5b01,0x1e5b0f,0x1e5b1d,0x1e5b0a,0x1e5b0a,0x1e5b0a}
        };
        for (long[] spec : switches) {
            var entry = toAddr(spec[0]);
            var branch = toAddr(spec[1]);
            var table = toAddr(spec[2]);
            int n = spec.length - 3;
            for (int i = 0; i < n; i++) {
                long actual = Integer.toUnsignedLong(currentProgram.getMemory().getInt(table.add(i*4)));
                if (actual != spec[3+i]) throw new Exception("Unexpected jump-table entry at " + table.add(i*4));
            }
            disassemble(entry);
            var f = getFunctionAt(entry);
            if (f == null) f = createFunction(entry,null);
            if (f == null) throw new Exception("Missing dispatcher " + entry);
            var instruction = getInstructionAt(branch);
            if (instruction == null || !instruction.getFlowType().isComputed() || !instruction.getFlowType().isJump())
                throw new Exception("Not an indirect jump at " + branch);
            ArrayList<Address> destinations = new ArrayList<>();
            for (int i = 0; i < n; i++) {
                var dest = toAddr(spec[3+i]);
                if (!destinations.contains(dest)) destinations.add(dest);
                disassemble(dest);
                currentProgram.getReferenceManager().addMemoryReference(branch,dest,
                    RefType.COMPUTED_JUMP,SourceType.USER_DEFINED,0);
            }
            clearListing(table,table.add(n*4-1));
            createData(table,new ArrayDataType(new PointerDataType(null,4,currentProgram.getDataTypeManager()),n,4));
            new JumpTable(branch,destinations,true,0).writeOverride(f);
            CreateFunctionCmd.fixupFunctionBody(currentProgram,f,monitor);
            setEOLComment(branch,"Reviewed table has " + n + " entries at " + table +
                "; input enum is decremented before indexing. No runtime bounds guard in original.");
            Files.deleteIfExists(out.resolve("decompiled/"+entry+".c"));
            for (var caller : f.getCallingFunctions(monitor))
                Files.deleteIfExists(out.resolve("decompiled/"+caller.getEntryPoint()+".c"));
        }
        Files.writeString(out.resolve("switch-recovery.json"),"{\"reviewed_switches\":2}\n");
        println("HALO2_SWITCHES_RECOVERED count=2");
    }
}
