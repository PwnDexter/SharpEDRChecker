using System;
using System.Collections.Generic;

namespace SharpEDRChecker
{
    class Program
    {
        static void Main(string[] args)
        {
            try
            {
                bool isAdm = PrivilegeChecker.PrivCheck();
                PrintIntro(isAdm);
                var summary = ProcessChecker.CheckProcesses();
                summary += ProcessChecker.CheckCurrentProcessModules();
                summary += DirectoryChecker.CheckDirectories();
                summary += ServiceChecker.CheckServices();
                summary += DriverChecker.CheckDrivers();
                PrintOutro(summary);
#if DEBUG
                Console.WriteLine("Press Enter to continue...");
                Console.ReadLine();
#endif
            }
            catch (Exception e)
            {
                Console.WriteLine("[-] Error running SharpEDRChecker: " + e.Message);
                Console.WriteLine(e.StackTrace);
            }
        }

        private static void PrintIntro(bool isAdm)
        {
            Console.WriteLine("\n[!] Welcome to EDRChecker by @PwnDexter\n");
            if(isAdm)
            {
                Console.WriteLine("[+] Running as admin, all checks will be performed\n");
            }
            else
            {
                Console.WriteLine("[-] Not running as admin, privileged metadata may not checked\n");
            }
        }

        private static void PrintOutro(string summary)
        {
            Console.WriteLine($"[!] The tldr is: {summary}\n");
            Console.WriteLine("[!] EDR Checks Complete\n");
        }
    }
}
