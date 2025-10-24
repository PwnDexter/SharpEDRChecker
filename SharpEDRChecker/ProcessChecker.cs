﻿using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Management;
using System.Text;

namespace SharpEDRChecker
{
    internal class ProcessChecker : IChecker
    {
        public string Name => "processes";
        public string Check()
        {
            try
            {
                Console.WriteLine("######################################");
                Console.WriteLine("[!][!][!] Checking processes [!][!][!]");
                Console.WriteLine("######################################\n");
                var wmiQuery = "Select Name, ExecutablePath, Description, Caption, CommandLine, ProcessId, ParentProcessId From Win32_Process";
                var processList = new ManagementObjectSearcher(wmiQuery).Get();
                var summaryBuilder = new StringBuilder();
                foreach (var process in processList)
                {
                    summaryBuilder.Append(CheckProcess(process));
                }
                if (summaryBuilder.Length == 0)
                {
                    Console.WriteLine("[+] No suspicious processes found\n");
                    return "\n[+] No suspicious processes found\n";
                }
                return $"\n[!] Process Summary: \n{summaryBuilder.ToString()}\n";
            }
            catch (Exception e)
            {
                Console.WriteLine($"[-] Errored on checking processes: {e.Message}\n{e.StackTrace}");
                return "\n[-] Errored on checking processes\n";
            }
        }

        private string CheckProcess(ManagementBaseObject process)
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
                    try
                    {
                        metadata = $"{FileChecker.GetFileInfo(processPath.ToString())}";
                        allattribs = $"{allattribs} - {metadata}";
                    }
                    catch (Exception e)
                    {
                        Console.WriteLine($"[-] Could not get file metadata for process binary: {processPath}\n[-] {e.Message}\n");
                    }
                }

                var matches = EDRMatcher.GetMatches(allattribs);

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
                                $"\n[!] Matched on: {string.Join(", ", matches.ToArray())}\n");
                    return $"\t[-] {processName} : {string.Join(", ", matches.ToArray())}\n";
                }
                return "";
            }
            catch (Exception e)
            {
                Console.WriteLine($"[-] Errored on checking individual process: {process["Name"]} : {process["ProcessId"]}\n{e.Message}\n{e.StackTrace}");
                return $"\t[-] {process["Name"]} : Failed to perform checks\n";
            }
        }
    }
}
