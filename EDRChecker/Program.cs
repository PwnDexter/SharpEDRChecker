using System;

namespace EDRChecker
{
    class Program
    {
        static void Main(string[] args)
        {
            PrintIntro();
            ProcessChecker.CheckProcesses();
            ProcessChecker.CheckCurrentProcessModules();
            DirectoryChecker.CheckDirectories();
            ServiceChecker.CheckServices();

            if (IsAdm() || ForceRegistryChecks(args))
            {
                RegistryChecker.CheckRegistry();
            }
            if (IsAdm())
            {
                DriverChecker.CheckDrivers();
            }
            PrintOutro();
        }

        private static void PrintIntro()
        {
            Console.WriteLine("Welcome to EDRChecker by @PwnDexter");
            Console.WriteLine("EDR Products to look for:");

            //Print the list of EDR Products
            foreach (string edr in EDRData.edrlist)
            {
                Console.WriteLine(edr);
            }
        }

        private static bool IsAdm()
        {
            Console.WriteLine("Checking Privileges Not Implemented");
            return true;
        }

        private static bool ForceRegistryChecks(string[] args)
        {
            Console.WriteLine("Checking Arguments Not Implemented");
            return true;
        }

        private static void PrintOutro()
        {
            Console.WriteLine("\nEDR Checks Complete");
        }
    }
}
