//Universal IOCTL extractor for ANY Windows driver
//@author Ladybug Fuzzer
//@category Analysis

import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.listing.*;
import java.io.*;
import java.util.*;
import java.util.regex.*;

public class analyze_ioctls_v2 extends GhidraScript {

    private Set<Long> foundIoctls = new TreeSet<>();
    private List<String> dangerousCalls = new ArrayList<>();
    private Map<Long, String> ioctlSources = new HashMap<>();
    private Set<Long> tableAddresses = new HashSet<>();
    
    private Function findDispatchFromEntry(Function entry) {
        // Look for param + 0xe0 assignment (IRP_MJ_DEVICE_CONTROL)
        DecompInterface decomp = new DecompInterface();
        decomp.openProgram(currentProgram);
        try {
            DecompileResults res = decomp.decompileFunction(entry, 60, monitor);
            if (res != null && res.decompileCompleted()) {
                String code = res.getDecompiledFunction().getC();
                // Match: param_1 + 0xe0) = FUN_xxxxxxxx
                Pattern pat = Pattern.compile("\\+ 0xe0\\)\\s*=\\s*(FUN_[0-9a-fA-F]+)");
                Matcher m = pat.matcher(code);
                if (m.find()) {
                    String funcName = m.group(1);
                    println("[*] Found DeviceControl handler: " + funcName);
                    Function f = getGlobalFunctions(funcName).get(0);
                    decomp.dispose();
                    return f;
                }
            }
        } catch (Exception e) {}
        decomp.dispose();
        return null;
    }
    
    @Override
    protected void run() throws Exception {
        println("=== LADYBUG UNIVERSAL IOCTL EXTRACTOR ===");
        println("Target: " + currentProgram.getName());
        
        println("\n[1/2] Finding IOCTL dispatch handler...");
        Function dispatchFunc = findDispatchFunction();
        
        if (dispatchFunc != null) {
            println("[+] Found dispatch: " + dispatchFunc.getName());
            println("\n[2/2] Extracting IOCTLs...");
            extractFromFunction(dispatchFunc);
            
            // Scan sub-functions (2 levels deep for HTTP.sys style)
            Set<Function> scanned = new HashSet<>();
            scanned.add(dispatchFunc);
            for (Function called : dispatchFunc.getCalledFunctions(monitor)) {
                if (!scanned.contains(called)) {
                    scanned.add(called);
                    extractFromFunction(called);
                    // Go one level deeper
                    for (Function sub : called.getCalledFunctions(monitor)) {
                        if (!scanned.contains(sub)) {
                            scanned.add(sub);
                            extractFromFunction(sub);
                        }
                    }
                }
            }
            
            // Scan for dispatch tables
            scanDispatchTables(dispatchFunc);
            
            // If we found very few IOCTLs, scan all functions
            if (foundIoctls.size() < 5) {
                println("[!] Found only " + foundIoctls.size() + " IOCTLs, scanning all functions...");
                scanAllFunctions();
            }
        } else {
            println("[!] No dispatch found, scanning all...");
            scanAllFunctions();
        }
        
        println("\n[+] Total IOCTLs: " + foundIoctls.size());
        saveResults();
    }
    
    private Function findDispatchFunction() {
        FunctionIterator funcs = currentProgram.getFunctionManager().getFunctions(true);
        List<Function> candidates = new ArrayList<>();
        
        // First: scan ALL functions for param+0xe0 = FUN_ pattern
        println("[*] Scanning for IRP_MJ_DEVICE_CONTROL (param + 0xe0) pattern...");
        funcs = currentProgram.getFunctionManager().getFunctions(true);
        while (funcs.hasNext()) {
            Function func = funcs.next();
            Function found = findDispatchFromEntry(func);
            if (found != null) return found;
        }
        
        // Second: by name
        funcs = currentProgram.getFunctionManager().getFunctions(true);
        while (funcs.hasNext()) {
            Function func = funcs.next();
            String name = func.getName().toLowerCase();
            // Skip guard/CFG functions
            if (name.contains("guard") || name.contains("_gs_") || name.startsWith("_")) continue;
            if (name.contains("devicecontrol") || name.contains("dispatch") || name.contains("ioctl")) {
                return func;
            }
        }
        
        funcs = currentProgram.getFunctionManager().getFunctions(true);
        while (funcs.hasNext()) {
            Function func = funcs.next();
            String name = func.getName().toLowerCase();
            if (name.contains("guard") || name.contains("_gs_")) continue;
            try {
                for (Function called : func.getCalledFunctions(monitor)) {
                    String calledName = called.getName().toLowerCase();
                    if (calledName.contains("iofcompleterequest")) {
                        candidates.add(func);
                        break;
                    }
                }
            } catch (Exception e) {}
        }
        
        Function best = null;
        long maxSize = 0;
        for (Function f : candidates) {
            long size = f.getBody().getNumAddresses();
            if (size > maxSize) {
                maxSize = size;
                best = f;
            }
        }
        return best;
    }
    
    private void extractFromFunction(Function func) {
        DecompInterface decomp = new DecompInterface();
        decomp.openProgram(currentProgram);
        
        try {
            DecompileResults res = decomp.decompileFunction(func, 60, monitor);
            if (res != null && res.decompileCompleted()) {
                String code = res.getDecompiledFunction().getC();
                if (code != null) {
                    extractAllIoctls(code, func.getName());
                    findDangerousAPIs(code, func.getName());
                }
            }
        } catch (Exception e) {}
        
        decomp.dispose();
    }
    
    private void scanDispatchTables(Function func) {
        // Find DAT_ references in IOCTL lookup patterns
        DecompInterface decomp = new DecompInterface();
        decomp.openProgram(currentProgram);
        
        try {
            DecompileResults res = decomp.decompileFunction(func, 60, monitor);
            if (res != null && res.decompileCompleted()) {
                String code = res.getDecompiledFunction().getC();
                
                // Look for IOCTL table pattern: &DAT_xxx + index * 4
                // This is used in dispatch tables like AFD
                Pattern tablePat = Pattern.compile("&(DAT_)([0-9a-fA-F]{8,16})\\s*\\+.*\\*\\s*4");
                Matcher m = tablePat.matcher(code);
                
                while (m.find()) {
                    long addr = Long.parseUnsignedLong(m.group(2), 16);
                    if (!tableAddresses.contains(addr)) {
                        tableAddresses.add(addr);
                        println("    [*] Found IOCTL table at 0x" + Long.toHexString(addr));
                        readIoctlTable(addr, 128);
                    }
                }
            }
        } catch (Exception e) {}
        decomp.dispose();
    }
    
    private void readIoctlTable(long tableAddr, int maxEntries) {
        println("    [*] Scanning table at 0x" + Long.toHexString(tableAddr));
        
        int firstDeviceType = -1;
        int invalidCount = 0;
        
        try {
            ghidra.program.model.address.Address addr = 
                currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(tableAddr);
            
            // Read up to maxEntries
            for (int i = 0; i < maxEntries; i++) {
                ghidra.program.model.address.Address entryAddr = addr.add(i * 4);
                int val = currentProgram.getMemory().getInt(entryAddr);
                long ioctl = val & 0xFFFFFFFFL;
                
                // Stop on null entry
                if (ioctl == 0) break;
                
                int deviceType = (int)((ioctl >> 16) & 0xFFFF);
                int method = (int)(ioctl & 0x3);
                
                // Track first device type seen
                if (firstDeviceType == -1 && deviceType > 0) {
                    firstDeviceType = deviceType;
                }
                
                // Stop if device type changes (hit garbage)
                if (firstDeviceType != -1 && deviceType != firstDeviceType) {
                    invalidCount++;
                    if (invalidCount >= 2) break; // 2 consecutive = end of table
                    continue;
                }
                invalidCount = 0;
                
                // Stricter IOCTL check
                boolean validType = (deviceType >= 0x01 && deviceType <= 0x50) || 
                                   (deviceType >= 0x8000 && deviceType <= 0x8FFF);
                boolean validRange = ioctl > 0x10000 && ioctl < 0x90000000L;
                
                if (validType && validRange) {
                    if (!foundIoctls.contains(ioctl)) {
                        foundIoctls.add(ioctl);
                        ioctlSources.put(ioctl, "table@" + Long.toHexString(tableAddr));
                        String[] methods = {"BUFFERED", "IN_DIRECT", "OUT_DIRECT", "NEITHER"};
                        println("    [+] 0x" + String.format("%08X", ioctl) + " [" + methods[method] + "]");
                    }
                }
            }
        } catch (Exception e) {
            println("    [!] Table read failed: " + e.getMessage());
        }
    }

    private void extractAllIoctls(String code, String funcName) {
        // Find ALL hex numbers 0x????????
        Pattern hexPat = Pattern.compile("0x([0-9a-fA-F]{7,8})");
        Matcher m = hexPat.matcher(code);
        
        while (m.find()) {
            try {
                long val = Long.parseLong(m.group(1), 16);
                
                // Decode IOCTL
                int deviceType = (int)((val >> 16) & 0xFFFF);
                int method = (int)(val & 0x3);
                
                // Stricter validation
                boolean validType = (deviceType >= 0x01 && deviceType <= 0x50) || 
                                   (deviceType >= 0x8000 && deviceType <= 0x8FFF);
                boolean validRange = val > 0x10000 && val < 0x90000000L;
                boolean notUnicode = (val & 0xFF00FF00L) != 0;
                
                if (validType && validRange && notUnicode) {
                    if (!foundIoctls.contains(val)) {
                        foundIoctls.add(val);
                        ioctlSources.put(val, funcName);
                        
                        String[] methods = {"BUFFERED", "IN_DIRECT", "OUT_DIRECT", "NEITHER"};
                        println("    [+] 0x" + String.format("%08X", val) + " [" + methods[method] + "]");
                    }
                }
            } catch (Exception e) {}
        }
    }
    
    private void scanAllFunctions() {
        DecompInterface decomp = new DecompInterface();
        decomp.openProgram(currentProgram);
        
        FunctionIterator funcs = currentProgram.getFunctionManager().getFunctions(true);
        int count = 0;
        
        while (funcs.hasNext() && !monitor.isCancelled()) {
            Function func = funcs.next();
            count++;
            
            try {
                DecompileResults res = decomp.decompileFunction(func, 30, monitor);
                if (res != null && res.decompileCompleted()) {
                    String code = res.getDecompiledFunction().getC();
                    if (code != null) {
                        extractAllIoctls(code, func.getName());
                        findDangerousAPIs(code, func.getName());
                    }
                }
            } catch (Exception e) {}
        }
        
        decomp.dispose();
    }
    
    private void findDangerousAPIs(String code, String funcName) {
        String[] dangerous = {
            "MmMapIoSpace", "MmUnmapIoSpace", "MmMapLockedPages",
            "__readmsr", "__writemsr", "wrmsr", "rdmsr",
            "ZwMapViewOfSection", "MmGetPhysicalAddress",
            "ProbeForRead", "ProbeForWrite"
        };
        for (String api : dangerous) {
            if (code.contains(api)) {
                String entry = api + " in " + funcName;
                if (!dangerousCalls.contains(entry)) {
                    dangerousCalls.add(entry);
                }
            }
        }
    }
    
    private void saveResults() throws Exception {
        String name = currentProgram.getName().replace(".sys", "").replace(".SYS", "");
        String scriptDir = getSourceFile().getParentFile().getAbsolutePath();
        String outPath = scriptDir + File.separator + name + "_ghidra_v2.json";
        
        PrintWriter w = new PrintWriter(new FileWriter(outPath));
        w.println("{");
        w.println("  \"driver\": \"" + currentProgram.getName() + "\",");
        w.println("  \"ioctl_count\": " + foundIoctls.size() + ",");
        
        w.println("  \"dangerous_functions\": [");
        int i = 0;
        for (String d : dangerousCalls) {
            w.print("    \"" + d.replace("\"", "'") + "\"");
            w.println(++i < dangerousCalls.size() ? "," : "");
        }
        w.println("  ],");
        
        String[] methods = {"BUFFERED", "IN_DIRECT", "OUT_DIRECT", "NEITHER"};
        String[] access = {"ANY", "READ", "WRITE", "READ|WRITE"};
        i = 0;
        
        for (Long ioctl : foundIoctls) {
            int m = (int)(ioctl & 0x3);
            int dt = (int)((ioctl >> 16) & 0xFFFF);
            int fn = (int)((ioctl >> 2) & 0xFFF);
            int ac = (int)((ioctl >> 14) & 0x3);
            
            w.println("  \"0x" + String.format("%08X", ioctl) + "\": {");
            w.println("    \"code\": " + ioctl + ",");
            w.println("    \"method\": \"" + methods[m] + "\",");
            w.println("    \"device_type\": \"0x" + String.format("%04X", dt) + "\",");
            w.println("    \"function\": \"0x" + String.format("%03X", fn) + "\",");
            w.println("    \"access\": \"" + access[ac] + "\",");
            w.println("    \"priority\": " + (m == 3 ? 90 : 50) + ",");
            w.println("    \"source\": \"" + ioctlSources.getOrDefault(ioctl, "unknown") + "\"");
            w.print("  }");
            w.println(++i < foundIoctls.size() ? "," : "");
        }
        
        w.println("}");
        w.close();
        
        println("\n[+] Saved to: " + outPath);
    }
}
