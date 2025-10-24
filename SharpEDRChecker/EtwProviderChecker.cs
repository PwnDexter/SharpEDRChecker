using Microsoft.Win32;
using System;
using System.Text;

namespace SharpEDRChecker
{
    internal class EtwProviderChecker : IChecker
    {
        public string Name => "etw";
        public string Check()
        {
            var summaryBuilder = new StringBuilder();
            try
            {
                Console.WriteLine("#############################################");
                Console.WriteLine("[!][!][!] Checking ETW Providers [!][!][!]");
                Console.WriteLine("#############################################\n");

                using (RegistryKey providersKey = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Publishers"))
                {
                    if (providersKey == null)
                    {
                        Console.WriteLine("[-] Could not open ETW providers registry key.");
                        return "";
                    }

                    foreach (string providerGuid in providersKey.GetSubKeyNames())
                    {
                        using (RegistryKey providerKey = providersKey.OpenSubKey(providerGuid))
                        {
                            if (providerKey == null) continue;

                            string providerName = providerKey.GetValue(null)?.ToString() ?? ""; // Default value is the name
                            string messageFileName = providerKey.GetValue("MessageFileName")?.ToString() ?? "";
                            string allattribs = $"{providerName} - {messageFileName}";

                            var matches = EDRMatcher.GetMatches(allattribs);
                            if (matches.Count > 0)
                            {
                                Console.WriteLine($"[-] Suspicious ETW provider found:" +
                                                  $"\n\tProvider Name: {providerName}" +
                                                  $"\n\tProvider GUID: {providerGuid}" +
                                                  $"\n\tBinary: {messageFileName}" +
                                                  $"\n[!] Matched on: {string.Join(", ", matches.ToArray())}\n");
                                summaryBuilder.Append($"\t[-] {providerName} : {string.Join(", ", matches.ToArray())}\n");
                            }
                        }
                    }
                }

                var summary = summaryBuilder.ToString();
                if (string.IsNullOrEmpty(summary))
                {
                    Console.WriteLine("[+] No suspicious ETW providers found\n");
                    return "\n[+] No suspicious ETW providers found\n";
                }
                return $"\n[!] ETW Provider Summary: \n{summary}\n";
            }
            catch (Exception e)
            {
                Console.WriteLine($"[-] Errored on checking ETW providers: {e.Message}\n{e.StackTrace}");
                return "\n[-] Errored on checking ETW providers\n";
            }
        }
    }
}
