using System;
using System.Management;
using System.Text;

namespace SharpEDRChecker
{
    internal class WmiConsumerChecker : IChecker
    {
        public string Name => "wmiconsumers";
        public string Check()
        {
            var summaryBuilder = new StringBuilder();
            try
            {
                Console.WriteLine("###########################################");
                Console.WriteLine("[!][!][!] Checking WMI Consumers [!][!][!]");
                Console.WriteLine("###########################################\n");

                // Check for different types of consumers
                summaryBuilder.Append(CheckConsumerType("CommandLineEventConsumer"));
                summaryBuilder.Append(CheckConsumerType("ActiveScriptEventConsumer"));
                summaryBuilder.Append(CheckConsumerType("LogFileEventConsumer"));

                var summary = summaryBuilder.ToString();
                if (string.IsNullOrEmpty(summary))
                {
                    Console.WriteLine("[+] No suspicious WMI consumers found\n");
                    return "\n[+] No suspicious WMI consumers found\n";
                }
                return $"\n[!] WMI Consumer Summary: \n{summary}\n";
            }
            catch (Exception e)
            {
                Console.WriteLine($"[-] Errored on checking WMI consumers: {e.Message}\n{e.StackTrace}");
                return "\n[-] Errored on checking WMI consumers\n";
            }
        }

        private string CheckConsumerType(string consumerClassName)
        {
            var summaryBuilder = new StringBuilder();
            ManagementObjectSearcher searcher = null;
            try
            {
                var scope = new ManagementScope(@"\\.\root\subscription");
                var query = new ObjectQuery($"SELECT * FROM {consumerClassName}");
                searcher = new ManagementObjectSearcher(scope, query);
                foreach (ManagementObject consumer in searcher.Get())
                {
                    string consumerName = consumer["Name"]?.ToString() ?? "N/A";
                    string details = "";
                    string allattribs = consumerName;

                    if (consumerClassName == "CommandLineEventConsumer")
                    {
                        details = $"CommandLine: {consumer["CommandLineTemplate"]}";
                        allattribs += $" - {consumer["CommandLineTemplate"]}";
                    }
                    else if (consumerClassName == "ActiveScriptEventConsumer")
                    {
                        details = $"ScriptingEngine: {consumer["ScriptingEngine"]}\n\tScript: {consumer["ScriptText"]}";
                        allattribs += $" - {consumer["ScriptText"]}";
                    }

                    var matches = EDRMatcher.GetMatches(allattribs);
                    if (matches.Count > 0)
                    {
                        Console.WriteLine($"[-] Suspicious WMI consumer found:" +
                                          $"\n\tName: {consumerName}" +
                                          $"\n\tType: {consumerClassName}" +
                                          $"\n\tDetails: {details}" +
                                          $"\n[!] Matched on: {string.Join(", ", matches.ToArray())}\n");
                        summaryBuilder.Append($"\t[-] {consumerName} ({consumerClassName}) : {string.Join(", ", matches.ToArray())}\n");
                    }
                }
            }
            catch (ManagementException) { /* This can happen if the WMI class doesn't exist, which is fine. */ }
            finally
            {
                searcher?.Dispose();
            }
            return summaryBuilder.ToString();
        }
    }
}
