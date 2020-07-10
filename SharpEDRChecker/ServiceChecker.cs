using System;
using System.ServiceProcess;

namespace SharpEDRChecker
{
    internal class ServiceChecker
    {
        internal static void CheckServices()
        {
            Console.WriteLine("[!] Checking Services");
            foreach (ServiceController service in ServiceController.GetServices())
            {
                Console.WriteLine($"{service.DisplayName} - {service.ServiceName} - {service.Status}");
            }
        }
    }
}