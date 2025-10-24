using System;
using System.Collections.Generic;
using System.IO;
using System.Management;
using System.Text;

namespace SharpEDRChecker
{
    internal class RemoteAccessToolChecker : IChecker
    {
        public string Name => "remoteaccesstools";

        private readonly List<string> _remoteAccessToolKeywords = new List<string>
        {
            "teamviewer",
            "anydesk",
            "vnc",
            "logmein",
            "screenconnect",
            "connectwise",
            "splashtop",
            "rdpwrap",
            "remotepc",
            "gotomypc"
        };

        public string Check()
        {
            var summaryBuilder = new StringBuilder();
            try
            {
                Console.WriteLine("##################################################");
                Console.WriteLine("[!][!][!] Checking for Remote Access Tools [!][!][!]");
                Console.WriteLine("##################################################\n");

                summaryBuilder.Append(CheckProcesses());
                summaryBuilder.Append(CheckDirectories());

                var summary = summaryBuilder.ToString();
                if (string.IsNullOrEmpty(summary))
                {
                    Console.WriteLine("[+] No common remote access tools found\n");
                    return "\n[+] No common remote access tools found\n";
                }
                return $"\n[!] Remote Access Tools Summary: \n{summary}\n";
            }
            catch (Exception e)
            {
                Console.WriteLine($"[-] Errored on checking for remote access tools: {e.Message}\n{e.StackTrace}");
                return "\n[-] Errored on checking for remote access tools\n";
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
                    foreach (var keyword in _remoteAccessToolKeywords)
                    {
                        if (allattribs.ToLower().Contains(keyword))
                        {
                            var processName = process["Name"]?.ToString() ?? "N/A";
                            Console.WriteLine($"[-] Remote access tool process found:" +
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
                Console.WriteLine($"[-] Could not complete process check for remote access tools: {e.Message}");
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
                        foreach (var keyword in _remoteAccessToolKeywords)
                        {
                            if (subDir.ToLower().Contains(keyword))
                            {
                                Console.WriteLine($"[-] Remote access tool directory found:" +
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
