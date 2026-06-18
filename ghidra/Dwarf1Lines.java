// Dwarf1Lines.java - apply source line comments from ps2_dwarf1 model JSON.
// Args: optional source substring, delta=0x0, mode=eol|repeatable|plate
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.*;
import com.google.gson.*;
import java.io.*;

public class Dwarf1Lines extends GhidraScript {
    JsonArray files;
    String filter = null;
    String mode = "eol";
    long delta = 0;
    int nSet, nSkip, nErr;

    public void run() throws Exception {
        parseArgs();
        JsonObject root = readModel(askModelFile());
        files = root.getAsJsonArray("files");
        JsonArray lines = root.getAsJsonArray("lines");
        Listing listing = currentProgram.getListing();
        int commentType = CodeUnit.EOL_COMMENT;
        if (mode.equals("repeatable")) commentType = CodeUnit.REPEATABLE_COMMENT;
        else if (mode.equals("plate")) commentType = CodeUnit.PLATE_COMMENT;
        println("line records=" + lines.size() + " filter=" + filter + " mode=" + mode + " delta=0x" + Long.toHexString(delta));

        for (JsonElement le : lines) {
            JsonArray row = le.getAsJsonArray();
            if (row.size() < 3 || row.get(1).isJsonNull()) { nSkip++; continue; }
            String file = fileFor(row.get(1).getAsInt());
            if (filter != null && (file == null || !file.contains(filter))) continue;
            long addrValue = row.get(0).getAsLong() + delta;
            int line = row.get(2).getAsInt();
            try {
                Address addr = toAddr(addrValue);
                CodeUnit cu = listing.getCodeUnitAt(addr);
                if (cu == null) { nSkip++; continue; }
                cu.setComment(commentType, shortName(file) + ":" + line);
                nSet++;
            } catch (Exception ex) {
                nErr++;
                if (nErr <= 20) println("ERR @" + Long.toHexString(addrValue) + ": " + ex);
            }
        }
        println("line comments set=" + nSet + " skipped=" + nSkip + " err=" + nErr);
    }

    void parseArgs() {
        String[] args = getScriptArgs();
        if (args == null) return;
        for (String arg : args) {
            if (arg == null || arg.isEmpty()) continue;
            if (arg.startsWith("delta=")) delta = Long.decode(arg.substring("delta=".length()));
            else if (arg.startsWith("mode=")) mode = arg.substring("mode=".length());
            else filter = arg;
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

    String fileFor(int id) {
        return (id >= 0 && id < files.size()) ? files.get(id).getAsString() : null;
    }

    String shortName(String path) {
        if (path == null) return "?";
        String p = path.replace('\\', '/');
        int slash = p.lastIndexOf('/');
        return slash >= 0 ? p.substring(slash + 1) : p;
    }
}
