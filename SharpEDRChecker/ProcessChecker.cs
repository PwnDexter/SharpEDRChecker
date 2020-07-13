using System;
using System.Diagnostics;
using System.Management;

namespace SharpEDRChecker
{
    internal class ProcessChecker
    {
        internal static void CheckProcesses()
        {
            Console.WriteLine("[!] Checking processes...");
            var processList = new ManagementObjectSearcher("Select * From Win32_Process").Get();
            bool foundSuspiciousProcess = false;
            foreach (var process in processList)
            {
                var processName = process["Name"];
                var processPath = process["ExecutablePath"];
                var allattribs = $"{processName} - {processPath}";

                if (processPath != null)
                {
                    allattribs = $"{allattribs} - {GetFileInfo(processPath.ToString())}";
                }

                foreach (var edrstring in EDRData.edrlist)
                {
                    if (allattribs.ToLower().Contains(edrstring.ToLower()))
                    {
                        Console.WriteLine("\n***PLZ READ HERE FOR SUSPICIOUS PROCESS***");
                        Console.WriteLine($"[-] Suspicious process found: {allattribs}");
                        Console.WriteLine($"[!] Matched on: {edrstring}\n");
                        foundSuspiciousProcess = true;
                    }
                }
            }
            if (!foundSuspiciousProcess)
            {
                Console.WriteLine("[+] No suspicious processes found\n");
            }
        }

        internal static void CheckCurrentProcessModules()
        {
            Console.WriteLine("[!] Checking modules loaded in your current process...");
            Process myproc = Process.GetCurrentProcess();
            bool foundSuspiciousModule = false;
            foreach (ProcessModule module in myproc.Modules)
            {
                var allattribs = $"{module.FileName} - {GetFileInfo(module.FileName)}";

                foreach (var edrstring in EDRData.edrlist)
                {
                    if (module.ToString().ToLower().Contains(edrstring.ToLower()))
                    {
                        Console.WriteLine("\n***PLZ READ HERE FOR SUSPICIOUS DLLS IN YER PROCESS***");
                        Console.WriteLine($"[-] {allattribs}");
                        Console.WriteLine($"[!] Matched on: {edrstring}\n");
                        foundSuspiciousModule = true;
                    }
                }
            }
            if (!foundSuspiciousModule)
            {
                Console.WriteLine("[+] No suspicious modules found in your process\n");
            }
        }

        private static string GetFileInfo(string filePath)
        {
            var fileVersionInfo = FileVersionInfo.GetVersionInfo(filePath.ToString());
            return $"{fileVersionInfo.ProductName} -" +
                $" {fileVersionInfo.FileName} -" +
                $" {fileVersionInfo.OriginalFilename} -" +
                $" {fileVersionInfo.InternalName} -" +
                $" {fileVersionInfo.CompanyName} -" +
                $" {fileVersionInfo.FileDescription} -" +
                $" {fileVersionInfo.ProductVersion} -" +
                $" {fileVersionInfo.Comments} -" +
                $" {fileVersionInfo.LegalCopyright} -" +
                $" {fileVersionInfo.LegalTrademarks}";
        }
    }
}