using System;
using System.Management;
using System.Diagnostics;
using System.ServiceProcess;
using System.Runtime.InteropServices;
using System.Text;

namespace SharpEDRChecker
{
    internal class DriverChecker
    {
        [DllImport("psapi")]
        private static extern bool EnumDeviceDrivers(
            [MarshalAs(UnmanagedType.LPArray, ArraySubType = UnmanagedType.U4)][In][Out] UInt32[] ddAddresses,
            UInt32 arraySizeBytes,
            [MarshalAs(UnmanagedType.U4)] out UInt32 bytesNeeded);

        [DllImport("psapi")]
        private static extern int GetDeviceDriverBaseName(
            UInt32 ddAddress,
            StringBuilder ddBaseName,
            int baseNameStringSizeChars);

        internal static void CheckDrivers()
        {
            UInt32 arraySize;
            UInt32 arraySizeBytes;
            UInt32[] ddAddresses;
            UInt32 bytesNeeded;
            bool success;

            // Figure out how large an array we need to hold the device driver 'load addresses'
            success = EnumDeviceDrivers(null, 0, out bytesNeeded);

            Console.WriteLine("Success? " + success);
            Console.WriteLine("Array bytes needed? " + bytesNeeded);

            if (!success)
            {
                Console.WriteLine("Call to EnumDeviceDrivers failed!");
                int error = Marshal.GetLastWin32Error();
                Console.WriteLine("The last Win32 Error was: " + error);
                return;
            }
            if (bytesNeeded == 0)
            {
                Console.WriteLine("Apparently, there were NO device drivers to enumerate.  Strange.");
                return;
            }
            // Allocate the array; as each ID is a 4-byte int, it should be 1/4th the size of bytesNeeded
            arraySize = bytesNeeded / 4;
            arraySizeBytes = bytesNeeded;
            ddAddresses = new UInt32[arraySize];

            // Now fill it
            success = EnumDeviceDrivers(ddAddresses, arraySizeBytes, out bytesNeeded);

            if (!success)
            {
                Console.WriteLine("Call to EnumDeviceDrivers failed!");
                int error = Marshal.GetLastWin32Error();
                Console.WriteLine("The last Win32 Error was: " + error);
                return;
            }
            for (int i = 0; i < arraySize; i++)
            {
                // If the length of the device driver base name is over 1000 characters, good luck to it.  :-)
                StringBuilder sb = new StringBuilder(1000);

                int result = GetDeviceDriverBaseName(ddAddresses[i], sb, sb.Capacity);

                if(result == 0)
                {
                    int error = Marshal.GetLastWin32Error();
                    Console.WriteLine("The last Win32 Error was: " + error);
                }
                else
                {
                    Console.WriteLine("Device driver LoadAddress: " + ddAddresses[i] + ", BaseName: " + sb.ToString());
                }

            }
        }
    }
}