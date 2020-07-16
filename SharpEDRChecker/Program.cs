using System;

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
            DirectoryChecker.CheckDirectories();
            ServiceChecker.CheckServices();
            DriverChecker.CheckDrivers();

            /*if (isAdm || ForceRegistryChecks(args))
            {
                //RegistryChecker.CheckRegistry();
            }

            if (isAdm)
            {
               //DriverChecker.CheckDrivers();
            }*/
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
                Console.WriteLine("[-] Not running as admin, process metadata, registry and drivers will not be checked");
                Console.WriteLine("[-] Use the -Force flag to force registry checks when not running as admin\n");
            }
        }

        private static bool ForceRegistryChecks(string[] args)
        {
            return false;
        }

        private static void PrintOutro()
        {
            Console.WriteLine("[!] EDR Checks Complete\n");
        }
    }
}
