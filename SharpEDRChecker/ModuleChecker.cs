using System;
using System.Diagnostics;
using System.Text;

namespace SharpEDRChecker
{
    internal class ModuleChecker : IChecker
    {
        public string Name => "modules";
        public string Check()
        {
            try
            {
                Console.WriteLine("###################################################################");
                Console.WriteLine("[!][!][!] Checking modules loaded in your current process [!][!][!]");
                Console.WriteLine("###################################################################\n");
                Process myproc = Process.GetCurrentProcess();
                var summaryBuilder = new StringBuilder();
                foreach (ProcessModule module in myproc.Modules)
                {
                    summaryBuilder.Append(CheckModule(module));
                }
                if (summaryBuilder.Length == 0)
                {
                    Console.WriteLine("[+] No suspicious modules found in your process\n");
                    return "\n[+] No suspicious modules found in your process\n";
                }
                return $"\n[!] Modload Summary: \n{summaryBuilder.ToString()}\n";
            }
            catch (Exception e)
            {
                Console.WriteLine($"[-] Errored on checking modloads: {e.Message}\n{e.StackTrace}");
                return "\n[-] Errored on checking modloads\n";
            }
        }

        private string CheckModule(ProcessModule module)
        {
            try
            {
                var metadata = $"{FileChecker.GetFileInfo(module.FileName)}";
                var allattribs = $"{module.FileName} - {metadata}";

                var matches = EDRMatcher.GetMatches(allattribs);

                if (matches.Count > 0)
                {
                    Console.WriteLine("[-] Suspicious modload found in your process:" +
                                $"\n\tSuspicious Module: {module.FileName}" +
                                $"\n\tFile Metadata: {metadata}" +
                                $"\n[!] Matched on: {string.Join(", ", matches.ToArray())}\n");
                    return $"\t[-] {module.FileName} : {string.Join(", ", matches.ToArray())}\n";
                }
                return "";
            }
            catch (Exception e)
            {
                Console.WriteLine($"[-] Errored on checking individual module: {module.FileName}\n{e.Message}\n{e.StackTrace}");
                return $"\t[-] {module.FileName} : Failed to perform checks\n";
            }
        }
    }
}
