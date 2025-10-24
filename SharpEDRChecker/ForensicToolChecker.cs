using System;
using System.Collections.Generic;
using System.IO;
using System.Management;
using System.Text;

namespace SharpEDRChecker
{
    internal class ForensicToolChecker : IChecker
    {
        public string Name => "forensictools";

        private readonly List<string> _forensicToolKeywords = new List<string>
        {
            "x-ways",
            "autopsy",
            "wireshark",
            "ftk imager",
            "encase",
            "volatility",
            "dumpit",
            "winpmem",
            "sysinternals",
            "procexp",
            "procmon",
            "tcpview",
            "redline",
            "magnet axiom"
        };

        public string Check()
        {
            var summaryBuilder = new StringBuilder();
            try
            {
                Console.WriteLine("#############################################");
                Console.WriteLine("[!][!][!] Checking for Forensic Tools [!][!][!]");
                Console.WriteLine("#############################################\n");

                summaryBuilder.Append(CheckProcesses());
                summaryBuilder.Append(CheckDirectories());

                var summary = summaryBuilder.ToString();
                if (string.IsNullOrEmpty(summary))
                {
                    Console.WriteLine("[+] No common forensic tools found\n");
                    return "\n[+] No common forensic tools found\n";
                }
                return $"\n[!] Forensic Tools Summary: \n{summary}\n";
            }
            catch (Exception e)
            {
                Console.WriteLine($"[-] Errored on checking for forensic tools: {e.Message}\n{e.StackTrace}");
                return "\n[-] Errored on checking for forensic tools\n";
            }
        }

        private string CheckProcesses()
        {
            var summaryBuilder = new StringBuilder();
            try
            {
                var wmiQuery = "Select Name, Description, Caption, CommandLine From Win32_Process";
                var processList = new ManagementObjectSearcher(wmiQuery).Get();

                foreach (var process in processList)
                {
                    var allattribs = $"{process["Name"]} - {process["Description"]} - {process["Caption"]} - {process["CommandLine"]}";
                    foreach (var keyword in _forensicToolKeywords)
                    {
                        if (allattribs.ToLower().Contains(keyword))
                        {
                            var processName = process["Name"]?.ToString() ?? "N/A";
                            Console.WriteLine($"[-] Suspicious forensic tool process found:" +
                                              $"\n\tProcess: {processName}" +
                                              $"\n\tCommandLine: {process["CommandLine"]}" +
                                              $"\n[!] Matched on: {keyword}\n");
                            summaryBuilder.Append($"\t[-] Process: {processName} : Matched on {keyword}\n");
                            break;
                        }
                    }
                }
            }
            catch (Exception e)
            {
                Console.WriteLine($"[-] Could not complete process check for forensic tools: {e.Message}");
            }
            return summaryBuilder.ToString();
        }

        private string CheckDirectories()
        {
            var summaryBuilder = new StringBuilder();
            var dirsToCheck = new List<string> {
                Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),
                Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86)
            };

            foreach (var dir in dirsToCheck)
            {
                try
                {
                    foreach (var subDir in Directory.GetDirectories(dir))
                    {
                        foreach (var keyword in _forensicToolKeywords)
                        {
                            if (subDir.ToLower().Contains(keyword))
                            {
                                Console.WriteLine($"[-] Suspicious forensic tool directory found:" +
                                                  $"\n\tDirectory: {subDir}" +
                                                  $"\n[!] Matched on: {keyword}\n");
                                summaryBuilder.Append($"\t[-] Directory: {subDir} : Matched on {keyword}\n");
                                break;
                            }
                        }
                    }
                }
                catch (UnauthorizedAccessException) { /* Ignore directories we can't access */ }
            }
            return summaryBuilder.ToString();
        }
    }
}
