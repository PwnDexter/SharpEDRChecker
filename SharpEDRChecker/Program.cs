using Microsoft.Win32;
using System;
using System.Security.Principal;

namespace SharpEDRChecker
{
    class Program
    {
        static void Main(string[] args)
        {
            bool isAdm = PrivilegeChecker.PrivCheck();
            PrintIntro(isAdm);
            ProcessChecker.CheckProcesses();
            ProcessChecker.CheckCurrentProcessModules();
            //DirectoryChecker.CheckDirectories();
            //ServiceChecker.CheckServices();
            
            if (isAdm || ForceRegistryChecks(args))
            {
                //RegistryChecker.CheckRegistry();
            }

            if (isAdm)
            {
               //DriverChecker.CheckDrivers();
            }
            PrintOutro();
        }

        private static void PrintIntro(bool isAdm)
        {
            Console.WriteLine("Welcome to EDRChecker by @PwnDexter\n");
            if(isAdm)
            {
                Console.WriteLine("[+] Running as admin, all checks will be performed");
            }
            else
            {
                Console.WriteLine("[-] Not running as admin, process metadata, registry and drivers will not be checked");
                Console.WriteLine("[-] Use the -Force flag to force registry checks when not running as admin");
            }
        }

        private static bool ForceRegistryChecks(string[] args)
        {
            return false;
        }

        private static void PrintOutro()
        {
            Console.WriteLine("\nEDR Checks Complete");
        }
    }
}
