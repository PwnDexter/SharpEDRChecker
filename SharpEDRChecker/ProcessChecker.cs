using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq.Expressions;
using System.Management;

namespace SharpEDRChecker
{
    internal class ProcessChecker
    {
        internal static string CheckProcesses()
        {
            try
            {
                Console.WriteLine("[!] Checking processes...");
                var processList = new ManagementObjectSearcher("Select * From Win32_Process").Get();
                string summary = "";
                foreach (var process in processList)
                {
                    summary += CheckProcess(process);
                }
                if (string.IsNullOrEmpty(summary))
                {
                    Console.WriteLine("[+] No suspicious processes found\n");
                    return "\n[+] No suspicious processes found\n";
                }
                return $"\nProcess Summary: \n{summary}\n";
            }
            catch (Exception e)
            {
                Console.WriteLine($"[-] Errored on getting processes: {e.Message}\n{e.StackTrace}");
                return "\n[-] Errored on getting processes\n";
            }
        }

        private static string CheckProcess(ManagementBaseObject process)
        {
            try
            {
                var processName = process["Name"];
                var processPath = process["ExecutablePath"];
                var processDescription = process["Description"];
                var processCaption = process["Caption"];
                var processCmdLine = process["CommandLine"];
                var processPID = process["ProcessId"];
                var processParent = process["ParentProcessId"];
                var metadata = "";

                var allattribs = $"{processName} - " +
                    $"{processPath} - " +
                    $"{processDescription} - " +
                    $"{processCaption} - " +
                    $"{processCmdLine}";

                if (processPath != null)
                {
                    metadata = $"{FileChecker.GetFileInfo(processPath.ToString())}";
                    allattribs = $"{allattribs} - {metadata}";
                }

                var matches = new List<string>();
                foreach (var edrstring in EDRData.edrlist)
                {
                    if (allattribs.ToLower().Contains(edrstring.ToLower()))
                    {
                        matches.Add(edrstring);
                    }
                }
                if (matches.Count > 0)
                {
                    Console.WriteLine($"[-] Suspicious process found:" +
                                $"\n\tName: {processName}" +
                                $"\n\tDescription: {processDescription}" +
                                $"\n\tCaption: {processCaption}" +
                                $"\n\tBinary: {processPath}" +
                                $"\n\tProcess ID: {processPID}" +
                                $"\n\tParent Process: {processParent}" +
                                $"\n\tProcess CmdLine: {processCmdLine}" +
                                $"\n\tFile Metadata: {metadata}" +
                                $"\n[!] Matched on: {string.Join(", ", matches)}\n");
                    return $"\t{processName} : {string.Join(", ", matches)}\n";
                }
                return "";
            }
            catch (Exception e)
            {
                Console.WriteLine($"[-] Errored on getting individual process: {process["Name"]} : {process["ProcessId"]}\n{e.Message}\n{e.StackTrace}");
                return $"\t{process["Name"]} : Failed to perform checks\n";
            }
        }

        internal static string CheckCurrentProcessModules()
        {
            try
            {
                Console.WriteLine("[!] Checking modules loaded in your current process...");
                Process myproc = Process.GetCurrentProcess();
                var summary = "";
                foreach (ProcessModule module in myproc.Modules)
                {
                    summary += CheckModule(module);
                }
                if (string.IsNullOrEmpty(summary))
                {
                    Console.WriteLine("[+] No suspicious modules found in your process\n");
                    return "\n[+] No suspicious modules found in your process\n";
                }
                return $"\nModload Summary: \n{summary}\n";
            }
            catch (Exception e)
            {
                Console.WriteLine($"[-] Errored on getting modloads: {e.Message}\n{e.StackTrace}");
                return "\n[-] Errored on getting processes\n";
            }
        }

        private static string CheckModule(ProcessModule module)
        {
            try
            {
                var metadata = $"{FileChecker.GetFileInfo(module.FileName)}";
                var allattribs = $"{module.FileName} - {metadata}";

                var matches = new List<string>();
                foreach (var edrstring in EDRData.edrlist)
                {
                    if (allattribs.ToString().ToLower().Contains(edrstring.ToLower()))
                    {
                        matches.Add(edrstring);
                    }
                }
                if (matches.Count > 0)
                {
                    Console.WriteLine("[-] Suspicious modload found in your process:" +
                                $"\n\tSuspicious Module: {module.FileName}" +
                                $"\n\tFile Metadata: {metadata}" +
                                $"\n[!] Matched on: {string.Join(", ", matches)}\n");
                    return $"\t{module.FileName} : {string.Join(", ", matches)}\n";
                }
                return "";
            }
            catch (Exception e)
            {
                Console.WriteLine($"[-] Errored on getting individual module: {module.FileName}\n{e.Message}\n{e.StackTrace}");
                return $"\t{module.FileName} : Failed to perform checks\n";
            }
        }
    }
}