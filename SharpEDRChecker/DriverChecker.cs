using System;
using System.Management;
using System.Diagnostics;
using System.ServiceProcess;

namespace SharpEDRChecker
{
    internal class DriverChecker
    {
        internal static void CheckDrivers()
        {
            /*Console.WriteLine("[!] Checking Drivers...");
            foreach (ServiceController driver in ServiceController.GetDevices())
            {
                Console.WriteLine($"{driver.DisplayName} {driver.ServiceName} {driver.Status} {driver.ServiceType}");
            }*/
            
            //TESTING METHOD
            /*SelectQuery query = new SelectQuery("Win32_BaseService");
            ManagementObjectSearcher searcher = new ManagementObjectSearcher(query);
            foreach (ManagementObject ManageObject in searcher.Get())
            {
                Console.WriteLine(ManageObject.GetPropertyValue("Name"));
                Console.WriteLine(ManageObject.GetPropertyValue("PathName"));
                Console.WriteLine(ManageObject.GetPropertyValue("Description"));
                Console.WriteLine(ManageObject.GetPropertyValue("Caption"));
                Console.WriteLine(ManageObject.GetPropertyValue("DisplayName"));
                Console.WriteLine(ManageObject.GetPropertyValue("SystemName"));
                Console.WriteLine(ManageObject.GetPropertyValue("StartName"));
                Console.WriteLine(ManageObject.GetPropertyValue("CreationClassName"));
                Console.WriteLine(ManageObject.GetPropertyValue("Started"));
                Console.WriteLine(ManageObject.GetPropertyValue("TagId"));
                Console.WriteLine(ManageObject.GetPropertyValue("SystemCreationClassNAme"));
            }*/


            
            //WORKING WMI FOR SYSTEMDRIVERS BUT NOT MINI FILTERS
            var driverList = new ManagementObjectSearcher("Select * From Win32_Service").Get();
            bool foundSuspiciousDriver = false;
            foreach (var driver in driverList)
            {
                foundSuspiciousDriver = CheckDriver(driver) || foundSuspiciousDriver;
            }
            if (!foundSuspiciousDriver)
            {
                Console.WriteLine("[+] No suspicious drivers found\n");
            }
        }

        private static bool CheckDriver(ManagementBaseObject driver)
        {
            bool foundSuspiciousDriver = false;
            var driverName = driver["Name"];
            var driverDisplayName = driver["DisplayName"];
            var driverDescription = driver["Description"];
            var driverCaption = driver["Caption"];
            var driverPathName = driver["PathName"];
            var driverState = driver["State"];
            var driverStartName = driver["StartName"];

            var allattribs = $"{driverName} - " +
                $"{driverDisplayName} - " +
                $"{driverDescription} - " +
                $"{driverCaption} - " +
                $"{driverPathName}";

            foreach (var edrstring in EDRData.edrlist)
            {
                if (allattribs.ToLower().Contains(edrstring.ToLower()))
                {
                    Console.WriteLine($"[-] Suspicious driver found:" +
                        $"\n\tName: {driverName}" +
                        $"\n\tDisplayName: {driverDisplayName}" +
                        $"\n\tDescription: {driverDescription}" +
                        $"\n\tCaption: {driverCaption}" +
                        $"\n\tBinary: {driverPathName}" +
                        $"\n\tStatus: {driverState}" +
                        $"\n\tStartName: {driverStartName}" +
                        $"\n[!] Matched on: {edrstring}\n");
                    foundSuspiciousDriver = true;
                }
            }
            return foundSuspiciousDriver;
        }
    }
}