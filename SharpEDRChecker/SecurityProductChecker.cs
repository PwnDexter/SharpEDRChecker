using System;
using System.Management;
using System.Text;

namespace SharpEDRChecker
{
    internal class SecurityProductChecker : IChecker
    {
        public string Name => "securityproducts";

        public string Check()
        {
            var summaryBuilder = new StringBuilder();
            try
            {
                Console.WriteLine("#####################################################");
                Console.WriteLine("[!][!][!] Checking Windows Security Products [!][!][!]");
                Console.WriteLine("#####################################################\n");

                summaryBuilder.Append(CheckProductType("AntiVirusProduct"));
                summaryBuilder.Append(CheckProductType("AntiSpywareProduct"));
                summaryBuilder.Append(CheckProductType("FirewallProduct"));

                var summary = summaryBuilder.ToString();
                if (string.IsNullOrEmpty(summary))
                {
                    Console.WriteLine("[+] No suspicious security products found via WMI\n");
                    return "\n[+] No suspicious security products found via WMI\n";
                }
                return $"\n[!] Security Products Summary: \n{summary}\n";
            }
            catch (Exception e)
            {
                Console.WriteLine($"[-] Errored on checking security products: {e.Message}\n{e.StackTrace}");
                return "\n[-] Errored on checking security products\n";
            }
        }

        private string CheckProductType(string productClassName)
        {
            var summaryBuilder = new StringBuilder();
            try
            {
                var scope = new ManagementScope(@"\\.\root\SecurityCenter2");
                var query = new ObjectQuery($"SELECT * FROM {productClassName}");
                using (var searcher = new ManagementObjectSearcher(scope, query))
                {
                    foreach (ManagementObject product in searcher.Get())
                    {
                        string displayName = product["displayName"]?.ToString() ?? "";
                        string exePath = product["pathToSignedProductExe"]?.ToString() ?? "";
                        string allattribs = $"{displayName} - {exePath}";

                        var matches = EDRMatcher.GetMatches(allattribs);
                        if (matches.Count > 0)
                        {
                            Console.WriteLine($"[-] Suspicious security product found:" +
                                              $"\n\tProduct Name: {displayName}" +
                                              $"\n\tProduct Type: {productClassName}" +
                                              $"\n\tExecutable Path: {exePath}" +
                                              $"\n[!] Matched on: {string.Join(", ", matches.ToArray())}\n");
                            summaryBuilder.Append($"\t[-] {displayName} ({productClassName}) : {string.Join(", ", matches.ToArray())}\n");
                        }
                    }
                }
            }
            catch (ManagementException) { /* This can happen if the WMI namespace/class doesn't exist, which is fine. */ }
            return summaryBuilder.ToString();
        }
    }
}
