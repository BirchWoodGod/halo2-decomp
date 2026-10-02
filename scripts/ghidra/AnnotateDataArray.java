// Apply instruction-reviewed custom ABI and types; project-assigned names.
// @category Halo2
import ghidra.app.script.GhidraScript;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.pcode.HighFunctionDBUtil;
import com.google.gson.*;
import java.nio.file.*;
import java.util.*;

public class AnnotateDataArray extends GhidraScript {
    private DataType u32 = UnsignedIntegerDataType.dataType;
    private Map<String, DataType> types = new HashMap<>();
    private void field(Structure s, int offset, DataType t, String name) {
        s.replaceAtOffset(offset, t, t.getLength(), name, null);
    }
    public void run() throws Exception {
        Path root = Paths.get(getScriptArgs()[0]);
        Files.deleteIfExists(root.resolve("analysis/abi-annotations.json"));
        if (!Files.exists(root.resolve("analysis/mapping-verification.json")))
            throw new Exception("VerifyMapping must succeed first");
        JsonObject catalog = JsonParser.parseString(Files.readString(root.resolve("config/data_array_abi.json"))).getAsJsonObject();
        if (!Files.readString(root.resolve("analysis/sha256.txt")).startsWith(catalog.get("xbe_sha256").getAsString()))
            throw new Exception("Wrong XBE build for ABI catalog");
        JsonObject bridge = JsonParser.parseString(Files.readString(root.resolve("config/host_bridge_abi.json"))).getAsJsonObject();
        if (!catalog.get("xbe_sha256").equals(bridge.get("xbe_sha256"))) throw new Exception("ABI profile mismatch");
        JsonArray functions = catalog.getAsJsonArray("functions");
        functions.addAll(bridge.getAsJsonArray("functions"));
        var manager = currentProgram.getDataTypeManager();
        DataType pointer = new PointerDataType(ByteDataType.dataType, 4, manager);
        var header = new StructureDataType(new CategoryPath("/Halo2"), "h2_data_array", 0x4c);
        field(header,0,new ArrayDataType(CharDataType.dataType,32,1),"name");
        field(header,0x20,u32,"capacity"); field(header,0x24,u32,"stride");
        field(header,0x28,ByteDataType.dataType,"alignment_bits");
        field(header,0x29,ByteDataType.dataType,"active");
        field(header,0x2a,ByteDataType.dataType,"flags");
        field(header,0x2c,u32,"signature"); field(header,0x30,pointer,"allocator");
        field(header,0x34,u32,"next_free"); field(header,0x38,u32,"high_water");
        field(header,0x3c,u32,"count"); field(header,0x40,UnsignedShortDataType.dataType,"next_salt");
        field(header,0x44,pointer,"elements"); field(header,0x48,pointer,"bitmap");
        DataType h = manager.addDataType(header, DataTypeConflictHandler.REPLACE_HANDLER);
        DataType hp = new PointerDataType(h,4,manager);
        var iterator = new StructureDataType(new CategoryPath("/Halo2"), "h2_data_iterator", 12);
        field(iterator,0,hp,"array"); field(iterator,4,u32,"handle"); field(iterator,8,u32,"index");
        DataType it = manager.addDataType(iterator,DataTypeConflictHandler.REPLACE_HANDLER);
        types.put("array_ptr",hp); types.put("iterator_ptr",new PointerDataType(it,4,manager));
        types.put("int32",IntegerDataType.dataType); types.put("uint32",u32); types.put("pointer",pointer);
        types.put("byte",ByteDataType.dataType);
        types.put("float32",FloatDataType.dataType);
        types.put("word",UnsignedShortDataType.dataType);
        types.put("string",new PointerDataType(CharDataType.dataType,4,manager));
        types.put("void",VoidDataType.dataType);
        Set<Function> refresh = new HashSet<>();
        // Reviewed CRT stack probe: probes pages and subtracts input EAX from
        // caller ESP. Treating this as an ordinary call corrupts stack recovery.
        byte[] probeBytes = HexFormat.of().parseHex(
            "85c074143d00100000730ef7d803c483c0048500948b0050c3518d4c240881e9001000002d0010000085013d0010000073ec2bc88bc485018be18b088b400450c3");
        if (!Arrays.equals(getBytes(toAddr(0x320560), probeBytes.length), probeBytes))
            throw new Exception("Unexpected CRT stack probe bytes");
        Function probe = getFunctionAt(toAddr(0x320560));
        if (probe == null) throw new Exception("Missing CRT stack probe function");
        probe.setCallFixup("alloca_probe");
        refresh.addAll(probe.getCallingFunctions(monitor));
        int count = 0;
        for (JsonElement item : functions) {
            JsonObject spec = item.getAsJsonObject();
            long address = Long.parseLong(spec.get("address").getAsString(),16);
            Function f = getFunctionAt(toAddr(address));
            if (f == null) {
                disassemble(toAddr(address));
                f = createFunction(toAddr(address),spec.get("name").getAsString());
            }
            if (f == null) throw new Exception("Missing function " + Long.toHexString(address));
            List<Variable> parameters = new ArrayList<>();
            for (JsonElement p : spec.getAsJsonArray("parameters")) {
                JsonObject param = p.getAsJsonObject();
                String name = param.get("name").getAsString(), storage = param.get("storage").getAsString();
                DataType type = types.get(param.get("type").getAsString());
                if (storage.startsWith("stack:"))
                    parameters.add(new ParameterImpl(name,type,Integer.parseInt(storage.substring(6)),currentProgram));
                else if (storage.startsWith("xmm"))
                    parameters.add(new ParameterImpl(name,type,new VariableStorage(currentProgram,currentProgram.getRegister(storage.toUpperCase()).getAddress(),type.getLength()),currentProgram));
                else parameters.add(new ParameterImpl(name,type,currentProgram.getRegister(storage.toUpperCase()),currentProgram));
            }
            String returnKind = spec.get("returns").getAsString();
            String returnRegister = spec.has("return_storage") ? spec.get("return_storage").getAsString().toUpperCase() : returnKind.equals("byte") ? "AL" : returnKind.equals("word") ? "AX" : "EAX";
            Variable ret = returnKind.equals("void") ? new ReturnParameterImpl(VoidDataType.dataType,currentProgram) :
                new ReturnParameterImpl(types.get(returnKind),new VariableStorage(currentProgram,currentProgram.getRegister(returnRegister).getAddress(),types.get(returnKind).getLength()),currentProgram);
            String convention = spec.has("calling_convention") ? spec.get("calling_convention").getAsString() : "__stdcall";
            f.updateFunction(convention,ret,parameters,Function.FunctionUpdateType.CUSTOM_STORAGE,true,SourceType.USER_DEFINED);
            f.setVarArgs(spec.has("variadic") && spec.get("variadic").getAsBoolean());
            f.setStackPurgeSize(spec.get("stack_purge").getAsInt());
            f.setName(spec.get("name").getAsString(),SourceType.USER_DEFINED);
            String source = spec.has("source") ? spec.get("source").getAsString() : "src/data_array.c";
            f.setComment("Project-assigned name. Reconstructed in " + source + ".\n" +
                "Custom register/stack ABI reviewed against original x86; differential tests under tests/.\n" +
                "See ENGINE.md for assumptions; this is not an original symbol.");
            refresh.add(f); refresh.addAll(f.getCallingFunctions(monitor));
            count++;
        }
        // These allocator vtable calls take ECX=this, one stack argument, and
        // callee cleanup. Without this override Ghidra mis-tracks ESP by four
        // bytes and turns the constructor's name into an apparent return address.
        long[][] allocatorCalls = {{0x16b59b,0x16b570,0},{0x16b5e9,0x16b5d0,1},
            {0x257d12,0x257d00,0},{0x257d4b,0x257d00,0},{0x1cec41,0x1cec30,0},
            {0x13e1b9,0x13e1a0,0},{0x1dfaf3,0x1dfae0,0},{0x7b3fd,0x7b3e0,0}};
        for (long[] call : allocatorCalls) {
            var address = toAddr(call[0]);
            var owner = getFunctionContaining(address);
            var instruction = getInstructionAt(address);
            if (owner == null || owner.getEntryPoint().getOffset() != call[1] ||
                instruction == null || !instruction.getFlowType().isCall() || !instruction.getFlowType().isComputed())
                throw new Exception("Unexpected allocator callsite " + address);
            boolean release = call[2] != 0;
            var prototype = new FunctionDefinitionDataType(release ? "host_allocator_release" : "host_allocator_allocate",manager);
            prototype.setCallingConvention("__thiscall");
            prototype.setReturnType(release ? VoidDataType.dataType : pointer);
            prototype.setArguments(new ParameterDefinition[] {
                new ParameterDefinitionImpl("allocator",pointer,null),
                new ParameterDefinitionImpl(release ? "allocation" : "size",release ? hp : u32,null)
            });
            HighFunctionDBUtil.writeOverride(owner,address,prototype);
            refresh.add(owner);
        }
        long[][] keyCalls = {{0x13e27f,0x13e270,1},{0x13e2d8,0x13e2d0,1},
            {0x13e2f9,0x13e2d0,2},{0x13e328,0x13e320,1},{0x13e348,0x13e320,2}};
        for (long[] call : keyCalls) {
            var address = toAddr(call[0]);
            var owner = getFunctionContaining(address);
            var instruction = getInstructionAt(address);
            if (owner == null || owner.getEntryPoint().getOffset() != call[1] ||
                instruction == null || !instruction.getFlowType().isCall() || !instruction.getFlowType().isComputed())
                throw new Exception("Unexpected key callback callsite " + address);
            var prototype = new FunctionDefinitionDataType(call[2] == 1 ? "engine_key_hash" : "engine_key_equal",manager);
            prototype.setCallingConvention("__stdcall");
            prototype.setReturnType(call[2] == 1 ? u32 : ByteDataType.dataType);
            ParameterDefinition[] parameters = new ParameterDefinition[(int)call[2]];
            for (int i=0;i<parameters.length;i++) parameters[i]=new ParameterDefinitionImpl("key"+i,u32,null);
            prototype.setArguments(parameters);
            HighFunctionDBUtil.writeOverride(owner,address,prototype);
            refresh.add(owner);
        }
        // A changed callee prototype can change its caller's pseudocode as well.
        for (Function f : refresh)
            Files.deleteIfExists(root.resolve("analysis/decompiled/" + f.getEntryPoint() + ".c"));
        Files.writeString(root.resolve("analysis/abi-annotations.json"),
            "{\"annotated\":"+count+",\"allocator_call_overrides\":"+allocatorCalls.length+
            ",\"key_call_overrides\":"+keyCalls.length+",\"invalidated_exports\":"+refresh.size()+"}\n");
        println("HALO2_ABI_ANNOTATED functions="+count+" exports_to_refresh="+refresh.size());
    }
}
