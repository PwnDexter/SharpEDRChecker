using System;
using System.Diagnostics;
using System.Management;
using System.Threading;

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
                var processDescription = process["Description"];
                var processCaption = process["Caption"];
                var processCmdLine = process["CommandLine"];
                var processPID = process["ProcessId"];
                var processParent = process["ParentProcessId"];
                var metadata = "";

                var allattribs = $"{processName} - " +
                    $"{processPath} - " +
                    $"{processDescription} - " +
                    $"{processCaption} - " +
                    $"{processCmdLine}";

                if (processPath != null)
                {
                    allattribs = $"{allattribs} - {GetFileInfo(processPath.ToString())}";
                    metadata = $"{GetFileInfo(processPath.ToString())}";
                }

                foreach (var edrstring in EDRData.edrlist)
                {
                    if (allattribs.ToLower().Contains(edrstring.ToLower()))
                    {
                        Console.WriteLine($"[-] Suspicious process found:" +
                            $"\n\tName: {processName}" +
                            $"\n\tDescription: {processDescription}" +
                            $"\n\tCaption: {processCaption}" +
                            $"\n\tBinary: {processPath}" +
                            $"\n\tProcess ID: {processPID}" +
                            $"\n\tParent Process: {processParent}" +
                            $"\n\tProcess CmdLine: {processCmdLine}" +
                            $"\n\tMetadata: {metadata}" +
                            $"\n[!] Matched on: {edrstring}\n");
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
                var metadata = $"{GetFileInfo(module.FileName)}";

                foreach (var edrstring in EDRData.edrlist)
                {
                    if (module.ToString().ToLower().Contains(edrstring.ToLower()))
                    {
                        Console.WriteLine("[-] Suspicious modload found in your process:" +
                            $"{metadata}" +
                            $"\n[!] Matched on: {edrstring}\n");
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
            return $"\n \t\t Product Name: {fileVersionInfo.ProductName}" +
                $"\n \t\t Filename: {fileVersionInfo.FileName}" +
                $"\n \t\t Original Filename: {fileVersionInfo.OriginalFilename}" +
                $"\n \t\t Internal Name: {fileVersionInfo.InternalName}" +
                $"\n \t\t Company Name: {fileVersionInfo.CompanyName}" +
                $"\n \t\t File Description: {fileVersionInfo.FileDescription}" +
                $"\n \t\t Product Version: {fileVersionInfo.ProductVersion}" +
                $"\n \t\t Comments: {fileVersionInfo.Comments}" +
                $"\n \t\t Legal Copyright: {fileVersionInfo.LegalCopyright}" +
                $"\n \t\t Legal Trademarks: {fileVersionInfo.LegalTrademarks}";
        }
    }
}