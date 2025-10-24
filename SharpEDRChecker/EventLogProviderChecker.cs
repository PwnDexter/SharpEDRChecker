using Microsoft.Win32;
using System;
using System.Text;

namespace SharpEDRChecker
{
    internal class EventLogProviderChecker : IChecker
    {
        public string Name => "eventlog";
        public string Check()
        {
            var summaryBuilder = new StringBuilder();
            try
            {
                Console.WriteLine("##############################################");
                Console.WriteLine("[!][!][!] Checking Event Log Providers [!][!][!]");
                Console.WriteLine("##############################################\n");

                using (RegistryKey providersKey = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services\EventLog"))
                {
                    if (providersKey == null) return "";

                    foreach (string logName in providersKey.GetSubKeyNames())
                    {
                        using (RegistryKey logKey = providersKey.OpenSubKey(logName))
                        {
                            if (logKey == null) continue;
                            foreach (string providerName in logKey.GetSubKeyNames())
                            {
                                var matches = EDRMatcher.GetMatches(providerName);
                                if (matches.Count > 0)
                                {
                                    Console.WriteLine($"[-] Suspicious event log provider found:" +
                                                      $"\n\tProvider: {providerName}" +
                                                      $"\n\tLog: {logName}" +
                                                      $"\n[!] Matched on: {string.Join(", ", matches.ToArray())}\n");
                                    summaryBuilder.Append($"\t[-] {providerName} : {string.Join(", ", matches.ToArray())}\n");
                                }
                            }
                        }
                    }
                }

                var summary = summaryBuilder.ToString();
                if (string.IsNullOrEmpty(summary))
                {
                    Console.WriteLine("[+] No suspicious event log providers found\n");
                    return "\n[+] No suspicious event log providers found\n";
                }
                return $"\n[!] Event Log Provider Summary: \n{summary}\n";
            }
            catch (Exception e)
            {
                Console.WriteLine($"[-] Errored on checking event log providers: {e.Message}\n{e.StackTrace}");
                return "\n[-] Errored on checking event log providers\n";
            }
        }
    }
}
