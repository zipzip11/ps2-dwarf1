// Dwarf1Globals.java - label and optionally type DWARF v1 global variables.
// Args: category=/dwarf1, delta=0x0, data=true
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.SourceType;
import com.google.gson.*;
import java.io.*;
import java.util.*;

public class Dwarf1Globals extends GhidraScript {
    DataTypeManager dtm;
    CategoryPath cat = new CategoryPath("/dwarf1");
    Map<Integer, JsonObject> rec = new HashMap<>();
    Map<Integer, DataType> cache = new HashMap<>();
    Map<String, Integer> nameCounts = new HashMap<>();
    long delta = 0;
    boolean createDataEnabled = true;
    int nData, nLabel, nDataErr, nSkipCode, nErr;

    public void run() throws Exception {
        dtm = currentProgram.getDataTypeManager();
        parseArgs();
        JsonObject root = readModel(askModelFile());
        JsonObject types = root.getAsJsonObject("types");
        for (Map.Entry<String, JsonElement> e : types.entrySet())
            rec.put(Integer.parseInt(e.getKey()), e.getValue().getAsJsonObject());
        buildNameCounts();
        JsonArray globals = root.getAsJsonArray("globals");
        println("globals in model=" + globals.size() + " category=" + cat + " delta=0x" + Long.toHexString(delta));

        for (JsonElement ge : globals) {
            JsonObject g = ge.getAsJsonObject();
            long raw = g.get("addr").getAsLong();
            long a = raw + delta;
            String nm = g.get("name").getAsString();
            Address addr = toAddr(a);
            try {
                DataType dt = resolve(g.getAsJsonObject("ref"));
                if (createDataEnabled && dt != null && dt.getLength() > 0 && getInstructionContaining(addr) == null) {
                    try {
                        clearListing(addr, addr.add(Math.max(dt.getLength(), 1) - 1));
                        createData(addr, dt);
                        nData++;
                    } catch (Exception de) { nDataErr++; }
                } else if (getInstructionContaining(addr) != null) {
                    nSkipCode++;
                }
                try { createLabel(addr, sanitize(nm), true, SourceType.IMPORTED); nLabel++; }
                catch (Exception ignored) {}
            } catch (Exception ex) {
                nErr++;
                if (nErr <= 20) println("ERR @" + Long.toHexString(a) + " " + nm + ": " + ex);
            }
        }
        println("data=" + nData + " labels=" + nLabel + " dataErr=" + nDataErr
            + " skippedInCode=" + nSkipCode + " err=" + nErr);
    }

    void parseArgs() {
        String[] args = getScriptArgs();
        if (args == null) return;
        for (String arg : args) {
            if (arg == null || arg.isEmpty()) continue;
            if (arg.startsWith("category=")) cat = new CategoryPath(arg.substring("category=".length()));
            else if (arg.startsWith("delta=")) delta = Long.decode(arg.substring("delta=".length()));
            else if (arg.startsWith("data=")) createDataEnabled = Boolean.parseBoolean(arg.substring("data=".length()));
        }
    }

    File askModelFile() throws Exception {
        File modelFile = askFile("Select ps2_dwarf1 model JSON", "Open");
        if (modelFile == null || !modelFile.isFile())
            throw new FileNotFoundException("Select an existing model JSON");
        println("model: " + modelFile.getAbsolutePath());
        return modelFile;
    }

    JsonObject readModel(File file) throws Exception {
        try (Reader r = new BufferedReader(new FileReader(file))) {
            return JsonParser.parseReader(r).getAsJsonObject();
        }
    }

    void buildNameCounts() {
        for (Map.Entry<Integer, JsonObject> e : rec.entrySet()) {
            JsonObject o = e.getValue();
            String nm = rawName(o);
            if (nm == null || nm.startsWith("@")) continue;
            String k = kind(o);
            if (!(isAggregate(k) || k.equals("enum") || k.equals("typedef"))) continue;
            String key = k + "|" + nm;
            nameCounts.put(key, nameCounts.getOrDefault(key, 0) + 1);
        }
    }

    DataType resolve(JsonObject ref) {
        if (ref == null || !ref.has("k")) return DataType.DEFAULT;
        String k = ref.get("k").getAsString();
        if (k.equals("f")) return fund(ref.get("t").getAsInt());
        if (k.equals("ptr") || k.equals("ref")) return new PointerDataType(resolve(ref.getAsJsonObject("e")), dtm);
        if (k.equals("const") || k.equals("vol") || k.equals("mod")) return resolve(ref.getAsJsonObject("e"));
        if (k.equals("u")) return resolveUdt(ref.get("o").getAsInt());
        return DataType.DEFAULT;
    }

    DataType resolveUdt(int off) {
        if (cache.containsKey(off)) return cache.get(off);
        JsonObject o = rec.get(off);
        if (o == null) return DataType.DEFAULT;
        String k = kind(o);
        DataType res;
        if (isAggregate(k) || k.equals("enum") || k.equals("typedef")) {
            res = dtm.getDataType(cat, typeName(o, off));
            if (res == null) res = DataType.DEFAULT;
        } else if (k.equals("array")) {
            DataType el = resolve(o.getAsJsonObject("ref"));
            if (el == null || el.getLength() <= 0) el = new ByteDataType();
            res = nestedArray(o, el);
        } else if (k.equals("func")) {
            res = dtm.getDataType(cat, "func_" + Integer.toHexString(off));
            if (res == null) res = new Undefined4DataType();
        } else if (k.equals("ptr") || k.equals("ref")) {
            res = new PointerDataType(resolve(o.getAsJsonObject("ref")), dtm);
        } else {
            res = DataType.DEFAULT;
        }
        cache.put(off, res);
        return res;
    }

    DataType nestedArray(JsonObject o, DataType el) {
        ArrayList<Integer> counts = new ArrayList<>();
        if (o.has("counts") && o.get("counts").isJsonArray()) {
            for (JsonElement e : o.getAsJsonArray("counts"))
                if (!e.isJsonNull()) counts.add(Math.max(1, e.getAsInt()));
        }
        if (counts.isEmpty()) counts.add(Math.max(1, intValue(o, "count", 1)));
        DataType cur = el;
        for (int i = counts.size() - 1; i >= 0; i--)
            cur = new ArrayDataType(cur, Math.max(1, counts.get(i)), Math.max(1, cur.getLength()));
        return cur;
    }

    DataType fund(int t) {
        switch (t) {
            case 0x01: return new CharDataType();
            case 0x02: return new SignedCharDataType();
            case 0x03: return new UnsignedCharDataType();
            case 0x04: case 0x05: return new ShortDataType();
            case 0x06: return new UnsignedShortDataType();
            case 0x07: case 0x08: return new IntegerDataType();
            case 0x09: return new UnsignedIntegerDataType();
            case 0x0a: case 0x0b: return new LongDataType();
            case 0x0c: return new UnsignedLongDataType();
            case 0x0e: return new FloatDataType();
            case 0x0f: return new DoubleDataType();
            case 0x10: return new LongDoubleDataType();
            case 0x14: return VoidDataType.dataType;
            case 0x15: return new BooleanDataType();
            case 0x8008: case 0x8208: return new LongLongDataType();
            case 0x8108: return new UnsignedLongLongDataType();
            default: return new Undefined4DataType();
        }
    }

    boolean isAggregate(String k) { return k.equals("struct") || k.equals("class") || k.equals("union"); }
    String kind(JsonObject o) { return o.has("kind") ? o.get("kind").getAsString() : ""; }
    String rawName(JsonObject o) { return o.has("name") && !o.get("name").isJsonNull() ? o.get("name").getAsString() : null; }
    int intValue(JsonObject o, String key, int def) { return o.has(key) && !o.get(key).isJsonNull() ? o.get(key).getAsInt() : def; }
    String typeName(JsonObject o, int off) {
        String nm = rawName(o);
        String k = kind(o);
        if (nm == null || nm.startsWith("@")) return "anon_" + Integer.toHexString(off);
        String clean = sanitize(nm);
        if (nameCounts.getOrDefault(k + "|" + nm, 0) > 1)
            return clean + "__" + Integer.toHexString(off);
        return clean;
    }
    String sanitize(String s) {
        StringBuilder b = new StringBuilder();
        for (int i = 0; i < s.length(); i++) {
            char ch = s.charAt(i);
            b.append((Character.isLetterOrDigit(ch) || ch == '_') ? ch : '_');
        }
        String r = b.toString();
        if (r.isEmpty()) r = "t";
        if (Character.isDigit(r.charAt(0))) r = "_" + r;
        return r;
    }
}
