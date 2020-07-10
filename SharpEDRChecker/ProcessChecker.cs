using System;
using System.Diagnostics;
using System.Management;

namespace SharpEDRChecker
{
    internal class ProcessChecker
    {
        internal static void CheckProcesses()
        {
            Console.WriteLine("\n[!] Checking processes...");
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

                foreach (var edr in EDRData.edrlist)
                {
                    if (allattribs.ToLower().Contains(edr.ToLower()))
                    {
                        Console.WriteLine("\n***PLZ READ HERE FOR SUSPICIOUS PROCESS***");
                        Console.WriteLine($"[-] {allattribs}");
                        Console.WriteLine($"\tmatched: {edr}\n");
                        foundSuspiciousProcess = true;
                    }
                }
            }
            if (!foundSuspiciousProcess)
            {
                Console.WriteLine("[+] No suspicious processes found");
            }
        }

        internal static void CheckCurrentProcessModules()
        {
            Console.WriteLine("\n[!] Checking modules loaded in your current process...");
            Process myproc = Process.GetCurrentProcess();
            bool foundSuspiciousModule = false;
            foreach (ProcessModule module in myproc.Modules)
            {
                var allattribs = $"{module.FileName} - {GetFileInfo(module.FileName)}";

                foreach (var edr in EDRData.edrlist)
                {
                    if (module.ToString().ToLower().Contains(edr.ToLower()))
                    {
                        Console.WriteLine("\n***PLZ READ HERE FOR SUSPICIOUS DLLS IN YER PROCESS***");
                        Console.WriteLine($"[-] {allattribs}");
                        Console.WriteLine($"\tmatched: {edr}\n");
                        foundSuspiciousModule = true;
                    }
                }
            }
            if (!foundSuspiciousModule)
            {
                Console.WriteLine("[+] No suspicious modules found in your process");
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