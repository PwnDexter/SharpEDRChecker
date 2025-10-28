﻿using Microsoft.Win32;
using System;
using System.Text;

namespace SharpEDRChecker
{
    internal class RegistryChecker : IChecker
    {
        public string Name => "registry";
        public string Check()
        {
            var summaryBuilder = new StringBuilder();
            try
            {
                Console.WriteLine("#####################################");
                Console.WriteLine("[!][!][!] Checking Registry [!][!][!]");
                Console.WriteLine("#####################################\n");

                string[] autorunKeys = {
                    // Standard autoruns
                    @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
                    @"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
                    @"SOFTWARE\Microsoft\Windows\CurrentVersion\RunServices",
                    @"SOFTWARE\Microsoft\Windows\CurrentVersion\RunServicesOnce",
                    // Winlogon
                    @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Notify",
                    // Shell extensions
                    @"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\ShellIconOverlayIdentifiers"
                };

                // Check HKLM and HKCU autorun keys
                summaryBuilder.Append(CheckHive(Registry.LocalMachine, autorunKeys));
                summaryBuilder.Append(CheckHive(Registry.CurrentUser, autorunKeys));

                var summary = summaryBuilder.ToString();
                if (string.IsNullOrEmpty(summary))
                {
                    Console.WriteLine("[+] No suspicious registry entries found\n");
                    return "\n[+] No suspicious registry entries found\n";
                }
                return $"\n[!] Registry Summary: \n{summary}\n";
            }
            catch (Exception e)
            {
                Console.WriteLine($"[-] Errored on checking registry: {e.Message}\n{e.StackTrace}");
                return "\n[-] Errored on checking registry\n";
            }
        }

        private string CheckHive(RegistryKey hive, string[] keyPaths)
        {
            var summaryBuilder = new StringBuilder();
            foreach (var path in keyPaths)
            {
                using (RegistryKey key = hive.OpenSubKey(path))
                {
                    if (key == null) continue;
                    try
                    {
                        foreach (string valueName in key.GetValueNames())
                        {
                            object value = key.GetValue(valueName);
                            string valueData;

                            if (value is string[] multiString)
                            {
                                valueData = string.Join(", ", multiString);
                            }
                            else
                            {
                                valueData = value?.ToString() ?? "";
                            }

                            string allattribs = $"{valueName} - {valueData}";
                            var matches = EDRMatcher.GetMatches(allattribs);
                            if (matches.Count > 0)
                            {
                                Console.WriteLine($"[-] Suspicious registry entry found:\n\tKey: {key.Name}\n\tValue: {valueName}\n\tData: {valueData}\n[!] Matched on: {string.Join(", ", matches.ToArray())}\n");
                                summaryBuilder.Append($"\t[-] {key.Name}\\{valueName} : {string.Join(", ", matches.ToArray())}\n");
                            }
                        }
                    }
                    catch (System.Security.SecurityException) { /* Ignore keys we can't access */ }
                    catch (Exception ex) { Console.WriteLine($"[-] Error reading registry key {key.Name}: {ex.Message}"); }
                }
            }
            return summaryBuilder.ToString();
        }
    }
}
