// Dwarf1Types.java - build DWARF v1 recovered types from ps2_dwarf1 model JSON.
// Run before Dwarf1Functions and Dwarf1Globals.
import ghidra.app.script.GhidraScript;
import ghidra.program.model.data.*;
import com.google.gson.*;
import java.io.*;
import java.util.*;

public class Dwarf1Types extends GhidraScript {
    DataTypeManager dtm;
    CategoryPath cat = new CategoryPath("/dwarf1");
    Map<Integer, JsonObject> rec = new HashMap<>();
    Map<Integer, DataType> dieToType = new HashMap<>();
    Map<Integer, DataType> memo = new HashMap<>();
    Map<String, Integer> nameCounts = new HashMap<>();
    int nStruct, nUnion, nEnum, nTypedef, nMemberOk, nMemberSkip;

    public void run() throws Exception {
        dtm = currentProgram.getDataTypeManager();
        parseArgs();
        JsonObject root = readModel(askModelFile());
        JsonObject types = root.getAsJsonObject("types");
        for (Map.Entry<String, JsonElement> e : types.entrySet())
            rec.put(Integer.parseInt(e.getKey()), e.getValue().getAsJsonObject());
        buildNameCounts();
        clearCategory();

        List<Integer> aggregates = new ArrayList<>();
        for (Map.Entry<Integer, JsonObject> e : rec.entrySet()) {
            String kind = kind(e.getValue());
            if (isAggregate(kind) || kind.equals("enum"))
                aggregates.add(e.getKey());
        }
        Collections.sort(aggregates);

        for (int off : aggregates) {
            JsonObject o = rec.get(off);
            String kind = kind(o);
            String name = typeName(o, off);
            DataType dt;
            if (kind.equals("union")) {
                dt = new UnionDataType(cat, name);
            } else if (kind.equals("enum")) {
                int size = (int) longValue(o, "size", 4);
                if (size != 1 && size != 2 && size != 4 && size != 8) size = 4;
                EnumDataType en = new EnumDataType(cat, name, size);
                if (o.has("consts")) {
                    for (JsonElement ce : o.getAsJsonArray("consts")) {
                        JsonArray pair = ce.getAsJsonArray();
                        try { en.add(sanitize(pair.get(0).getAsString()), pair.get(1).getAsLong()); }
                        catch (Exception ignored) {}
                    }
                }
                dt = en;
            } else {
                int size = Math.max(0, (int) longValue(o, "size", 0));
                dt = new StructureDataType(cat, name, size);
            }
            DataType managed = dtm.addDataType(dt, DataTypeConflictHandler.DEFAULT_HANDLER);
            dieToType.put(off, managed);
        }

        for (int off : aggregates) {
            JsonObject o = rec.get(off);
            String kind = kind(o);
            DataType dt = dieToType.get(off);
            if (kind.equals("struct") || kind.equals("class")) {
                Structure s = (Structure) dt;
                for (JsonElement me : array(o, "members")) {
                    JsonObject m = me.getAsJsonObject();
                    int moff = intValue(m, "off", -1);
                    DataType mt = resolve(m.getAsJsonObject("ref"));
                    if (mt == null || mt.getLength() <= 0 || moff < 0) { nMemberSkip++; continue; }
                    try {
                        s.replaceAtOffset(moff, mt, mt.getLength(), sanitize(m.get("name").getAsString()), null);
                        nMemberOk++;
                    } catch (Exception ex) { nMemberSkip++; }
                }
                nStruct++;
            } else if (kind.equals("union")) {
                Union u = (Union) dt;
                for (JsonElement me : array(o, "members")) {
                    JsonObject m = me.getAsJsonObject();
                    DataType mt = resolve(m.getAsJsonObject("ref"));
                    if (mt == null || mt.getLength() <= 0) { nMemberSkip++; continue; }
                    try {
                        u.add(mt, sanitize(m.get("name").getAsString()), null);
                        nMemberOk++;
                    } catch (Exception ex) { nMemberSkip++; }
                }
                nUnion++;
            } else if (kind.equals("enum")) {
                nEnum++;
            }
        }

        for (Map.Entry<Integer, JsonObject> e : rec.entrySet()) {
            if (kind(e.getValue()).equals("typedef"))
                resolveUdt(e.getKey());
        }

        println("DWARF1 types built in " + cat + ": struct/class=" + nStruct
            + " union=" + nUnion + " enum=" + nEnum + " typedef=" + nTypedef
            + " membersOk=" + nMemberOk + " membersSkipped=" + nMemberSkip);
    }

    void parseArgs() {
        String[] args = getScriptArgs();
        if (args == null) return;
        for (String arg : args) {
            if (arg.startsWith("category="))
                cat = new CategoryPath(arg.substring("category=".length()));
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

    void clearCategory() {
        Category c = dtm.getCategory(cat);
        if (c == null) return;
        DataType[] arr = c.getDataTypes();
        for (DataType dt : arr) {
            try { dtm.remove(dt, monitor); } catch (Exception ignored) {}
        }
        println("cleared previous " + cat + " direct types: " + arr.length);
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
        if (dieToType.containsKey(off)) return dieToType.get(off);
        if (memo.containsKey(off)) return memo.get(off);
        JsonObject o = rec.get(off);
        if (o == null) return DataType.DEFAULT;
        String k = kind(o);
        DataType res;
        if (k.equals("array")) {
            DataType el = resolve(o.getAsJsonObject("ref"));
            if (el == null || el.getLength() <= 0) el = new ByteDataType();
            res = nestedArray(o, el);
        } else if (k.equals("func")) {
            FunctionDefinitionDataType fd = new FunctionDefinitionDataType(cat, "func_" + Integer.toHexString(off));
            memo.put(off, fd);
            fd.setReturnType(resolve(o.getAsJsonObject("ret")));
            JsonArray ps = array(o, "params");
            ParameterDefinition[] pd = new ParameterDefinition[ps.size()];
            for (int i = 0; i < ps.size(); i++)
                pd[i] = new ParameterDefinitionImpl(null, resolve(ps.get(i).getAsJsonObject()), null);
            try { fd.setArguments(pd); } catch (Exception ignored) {}
            res = dtm.addDataType(fd, DataTypeConflictHandler.DEFAULT_HANDLER);
        } else if (k.equals("ptr") || k.equals("ref")) {
            res = new PointerDataType(resolve(o.getAsJsonObject("ref")), dtm);
        } else if (k.equals("typedef")) {
            String nm = typeName(o, off);
            DataType base = resolve(o.getAsJsonObject("ref"));
            if (base == null) base = DataType.DEFAULT;
            res = dtm.addDataType(new TypedefDataType(cat, nm, base), DataTypeConflictHandler.DEFAULT_HANDLER);
            nTypedef++;
        } else if (isAggregate(k) || k.equals("enum")) {
            res = dtm.getDataType(cat, typeName(o, off));
            if (res == null) res = DataType.DEFAULT;
        } else {
            res = DataType.DEFAULT;
        }
        memo.put(off, res);
        return res;
    }

    DataType nestedArray(JsonObject o, DataType el) {
        ArrayList<Integer> counts = new ArrayList<>();
        if (o.has("counts") && o.get("counts").isJsonArray()) {
            for (JsonElement e : o.getAsJsonArray("counts")) {
                if (!e.isJsonNull()) counts.add(Math.max(1, e.getAsInt()));
            }
        }
        if (counts.isEmpty()) counts.add(Math.max(1, intValue(o, "count", 1)));
        DataType cur = el;
        for (int i = counts.size() - 1; i >= 0; i--) {
            int len = Math.max(1, counts.get(i));
            int elemLen = Math.max(1, cur.getLength());
            cur = new ArrayDataType(cur, len, elemLen);
        }
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

    boolean isAggregate(String k) {
        return k.equals("struct") || k.equals("class") || k.equals("union");
    }

    String kind(JsonObject o) {
        return o.has("kind") ? o.get("kind").getAsString() : "";
    }

    JsonArray array(JsonObject o, String key) {
        return o.has(key) && o.get(key).isJsonArray() ? o.getAsJsonArray(key) : new JsonArray();
    }

    String rawName(JsonObject o) {
        return o.has("name") && !o.get("name").isJsonNull() ? o.get("name").getAsString() : null;
    }

    long longValue(JsonObject o, String key, long def) {
        return o.has(key) && !o.get(key).isJsonNull() ? o.get(key).getAsLong() : def;
    }

    int intValue(JsonObject o, String key, int def) {
        return o.has(key) && !o.get(key).isJsonNull() ? o.get(key).getAsInt() : def;
    }

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
