using System;

namespace SharpEDRChecker
{
    class Program
    {
        static void Main()
        {
            bool isAdm = PrivilegeChecker.PrivCheck();
            PrintIntro(isAdm);
            ProcessChecker.CheckProcesses();
            ProcessChecker.CheckCurrentProcessModules();
            DirectoryChecker.CheckDirectories();
            ServiceChecker.CheckServices();
            DriverChecker.CheckDrivers();
            PrintOutro();
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

        private static void PrintOutro()
        {
            Console.WriteLine("[!] EDR Checks Complete\n");
            Console.WriteLine("[!] TLDR:\n");
        }
    }
}