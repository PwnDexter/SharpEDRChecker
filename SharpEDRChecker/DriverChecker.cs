using System;
using System.ServiceProcess;

namespace SharpEDRChecker
{
    internal class DriverChecker
    {
        internal static void CheckDrivers()
        {
            Console.WriteLine("[!] Checking Drivers");
            foreach (ServiceController driver in ServiceController.GetDevices())
            {
                Console.WriteLine($"{driver.DisplayName} {driver.ServiceName} {driver.Status} {driver.ServiceType}");
            }
        }
    }
}