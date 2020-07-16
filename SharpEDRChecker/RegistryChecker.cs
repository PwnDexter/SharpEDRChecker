using System;

namespace SharpEDRChecker
{
    internal class RegistryChecker
    {
        internal static void CheckRegistry()
        {
            //if ($reg = Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\*' | Select-Object PSChildName,PSPath,DisplayName,ImagePath,Description) 
            Console.WriteLine("Checking Registry Not Implemented");
            //RegistryKey keys = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services\");
            //Console.WriteLine(keys);

            //public static string[] regkeys = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services\").GetSubKeyNames();
            
            /*foreach (string key in regkeys)
                {
                    Console.WriteLine(key);
                }*/


            /*if (regkeys != null) 
            { 
                Console.WriteLine(regkeys.GetValue(regkeys.Name);
                //Console.WriteLine(keys1.GetValue("Setting2"));
                keys1.Close();
            }*/

        }
    }
}