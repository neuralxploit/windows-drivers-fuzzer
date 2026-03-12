//Extracts IOCTL codes from Windows kernel drivers for Ladybug fuzzer
//@author Ladybug Fuzzer
//@category Analysis
//@keybinding
//@menupath
//@toolbar

import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;
import java.io.FileWriter;
import java.io.PrintWriter;
import java.util.*;
import java.util.regex.*;

public class analyze_ioctls extends GhidraScript {

    private DecompInterface decompiler;
    private Set<Long> foundIoctls = new TreeSet<>();
    private List<String> dangerousCalls = new ArrayList<>();
    private String dispatchHandler = null;
    
    // Valid device types for third-party drivers
    private static final Set<Integer> VALID_DEVICE_TYPES = new HashSet<>(Arrays.asList(
        0x0012, // FILE_DEVICE_NETWORK
        0x0022, // FILE_DEVICE_UNKNOWN (most common!)
        0x0027, // FILE_DEVICE_DISK_FILE_SYSTEM
        0x0029, // FILE_DEVICE_NETWORK_FILE_SYSTEM
        0x002D, // FILE_DEVICE_KS
        0x0034, // FILE_DEVICE_KSEC
        0x0038, // FILE_DEVICE_CRYPT_PROVIDER
        0x0039, // FILE_DEVICE_WPD
        0x003E, // FILE_DEVICE_BIOMETRIC
        0x8000  // Custom
    ));
    
    // Dangerous function patterns
    private static final String[] DANGEROUS_FUNCS = {
        "memcpy", "memmove", "RtlCopyMemory", "RtlMoveMemory",
        "strcpy", "strncpy", "wcscpy", "sprintf",
        "ProbeForRead", "ProbeForWrite",
        "MmMapLockedPages", "ExAllocatePool"
    };

    @Override
    protected void run() throws Exception {
        println("============================================================");
        println("  LADYBUG IOCTL ANALYZER");
        println("  Target: " + currentProgram.getName());
        println("============================================================");
        
        // Initialize decompiler
        decompiler = new DecompInterface();
        decompiler.openProgram(currentProgram);
        
        // Find and analyze all functions
        println("[*] Analyzing functions for IOCTL codes...");
        FunctionIterator functions = currentProgram.getFunctionManager().getFunctions(true);
        int funcCount = 0;
        
        while (functions.hasNext() && !monitor.isCancelled()) {
            Function func = functions.next();
            funcCount++;
            
            if (funcCount % 100 == 0) {
                println("    Processed " + funcCount + " functions, found " + foundIoctls.size() + " IOCTLs...");
            }
            
            analyzeFunction(func);
        }
        
        println("[+] Analyzed " + funcCount + " functions");
        println("[+] Found " + foundIoctls.size() + " potential IOCTLs");
        
        // Save results
        saveResults();
        
        decompiler.dispose();
        
        println("============================================================");
        println("  ANALYSIS COMPLETE");
        println("============================================================");
    }
    
    private void analyzeFunction(Function func) {
        try {
            DecompileResults results = decompiler.decompileFunction(func, 30, monitor);
            if (results == null || !results.decompileCompleted()) {
                return;
            }
            
            String decompiledCode = results.getDecompiledFunction().getC();
            if (decompiledCode == null) {
                return;
            }
            
            // Check for dispatch handler indicators
            if (decompiledCode.contains("IoControlCode") || 
                decompiledCode.contains("DeviceIoControl") ||
                decompiledCode.contains("IRP_MJ_DEVICE_CONTROL")) {
                if (dispatchHandler == null) {
                    dispatchHandler = func.getName();
                    println("[+] Found dispatch handler: " + func.getName() + " at " + func.getEntryPoint());
                }
            }
            
            // Extract hex constants that look like IOCTLs
            Pattern pattern = Pattern.compile("0x([0-9a-fA-F]{5,8})");
            Matcher matcher = pattern.matcher(decompiledCode);
            
            while (matcher.find()) {
                try {
                    long value = Long.parseLong(matcher.group(1), 16);
                    if (isValidIoctl(value)) {
                        foundIoctls.add(value);
                    }
                } catch (NumberFormatException e) {
                    // Ignore
                }
            }
            
            // Check for dangerous function calls
            for (String dangerous : DANGEROUS_FUNCS) {
                if (decompiledCode.contains(dangerous)) {
                    String entry = dangerous + " called in " + func.getName();
                    if (!dangerousCalls.contains(entry)) {
                        dangerousCalls.add(entry);
                    }
                }
            }
            
        } catch (Exception e) {
            // Ignore decompilation errors
        }
    }
    
    private boolean isValidIoctl(long value) {
        if (value == 0 || value == 0xFFFFFFFFL) {
            return false;
        }
        
        int deviceType = (int)((value >> 16) & 0xFFFF);
        int function = (int)((value >> 2) & 0xFFF);
        
        // Check device type
        if (!VALID_DEVICE_TYPES.contains(deviceType)) {
            return false;
        }
        
        // Function code should be reasonable
        if (function == 0 || function == 0xFFF) {
            return false;
        }
        
        return true;
    }
    
    private void saveResults() throws Exception {
        String driverName = currentProgram.getName().replace(".sys", "").replace(".SYS", "");
        String scriptDir = getSourceFile().getParentFile().getAbsolutePath();
        String outputPath = scriptDir + File.separator + driverName + "_ghidra_analysis.json";
        
        println("[*] Saving results to: " + outputPath);
        
        PrintWriter writer = new PrintWriter(new FileWriter(outputPath));
        writer.println("{");
        writer.println("  \"driver\": \"" + currentProgram.getName() + "\",");
        writer.println("  \"driver_path\": \"" + currentProgram.getExecutablePath() + "\",");
        writer.println("  \"dispatch_handler\": \"" + (dispatchHandler != null ? dispatchHandler : "unknown") + "\",");
        writer.println("  \"ioctl_count\": " + foundIoctls.size() + ",");
        
        // Write dangerous functions
        writer.println("  \"dangerous_functions\": [");
        int i = 0;
        for (String danger : dangerousCalls) {
            writer.print("    \"" + danger + "\"");
            if (++i < dangerousCalls.size()) writer.println(",");
            else writer.println();
        }
        writer.println("  ],");
        
        // Write IOCTLs in Ladybug format
        String[] methods = {"BUFFERED", "IN_DIRECT", "OUT_DIRECT", "NEITHER"};
        String[] access = {"ANY", "READ", "WRITE", "READ|WRITE"};
        
        i = 0;
        for (Long ioctl : foundIoctls) {
            int method = (int)(ioctl & 0x3);
            int accessBits = (int)((ioctl >> 14) & 0x3);
            int deviceType = (int)((ioctl >> 16) & 0xFFFF);
            int function = (int)((ioctl >> 2) & 0xFFF);
            
            String warning = (method == 3) ? "METHOD_NEITHER - user pointers passed directly!" : null;
            int priority = (method == 3) ? 90 : 50;
            
            writer.println("  \"0x" + String.format("%08X", ioctl) + "\": {");
            writer.println("    \"code\": " + ioctl + ",");
            writer.println("    \"min_input_size\": 0,");
            writer.println("    \"max_input_size\": 4096,");
            writer.println("    \"min_output_size\": 0,");
            writer.println("    \"method\": \"" + methods[method] + "\",");
            writer.println("    \"access\": \"" + access[accessBits] + "\",");
            writer.println("    \"device_type\": \"0x" + String.format("%04X", deviceType) + "\",");
            writer.println("    \"function\": \"0x" + String.format("%03X", function) + "\",");
            if (warning != null) {
                writer.println("    \"warning\": \"" + warning + "\",");
            } else {
                writer.println("    \"warning\": null,");
            }
            writer.println("    \"priority\": " + priority);
            writer.print("  }");
            if (++i < foundIoctls.size()) writer.println(",");
            else writer.println();
        }
        
        writer.println("}");
        writer.close();
        
        // Print summary
        println("\n[+] SUMMARY:");
        println("    IOCTLs found: " + foundIoctls.size());
        println("    Dangerous calls: " + dangerousCalls.size());
        
        int methodNeither = 0;
        for (Long ioctl : foundIoctls) {
            if ((ioctl & 0x3) == 3) methodNeither++;
        }
        println("    METHOD_NEITHER (high priority): " + methodNeither);
        
        if (foundIoctls.size() > 0) {
            println("\n[+] Sample IOCTLs:");
            int count = 0;
            for (Long ioctl : foundIoctls) {
                if (count++ >= 10) break;
                int method = (int)(ioctl & 0x3);
                String[] m = {"BUFFERED", "IN_DIRECT", "OUT_DIRECT", "NEITHER"};
                println("    0x" + String.format("%08X", ioctl) + " [" + m[method] + "]");
            }
            if (foundIoctls.size() > 10) {
                println("    ... and " + (foundIoctls.size() - 10) + " more");
            }
        }
        
        println("\n[+] Saved to: " + outputPath);
        println("[+] Use with: ladybug --device \\\\.\\DRIVER --analysis " + driverName + "_ghidra_analysis.json");
    }
}
