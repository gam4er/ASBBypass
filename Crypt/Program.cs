﻿using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;


namespace Aes_Example
{
    class AesExample
    {
        public static byte[] myIV;//= new byte[] { 40, 58, 32, 174, 187, 91, 201, 68, 81, 201, 230, 98, 222, 237, 26, 145 };
        public static byte[] myKey; //= new byte[] { 141, 46, 84, 223, 171, 106, 191, 231, 223, 254, 202, 22, 25, 216, 114, 211, 134, 201, 239, 179, 80, 64, 238, 106, 174, 7, 173, 31, 14, 142, 140, 179 };

        public static void Main()
        {
            Aes _algorithm = Aes.Create();
            _algorithm.GenerateIV();
            _algorithm.GenerateKey();

            myIV = _algorithm.IV;
            myKey = _algorithm.Key;


            byte[] SHound = File.ReadAllBytes(@"e:\Documents\GitHub\SharpHound3\SharpHound3\bin\Release\Confused\SharpHound.exe");


            File.WriteAllBytes(@"..\..\..\SHound\SHound.enc", Encrypt(SHound));

            File.WriteAllBytes(@"..\..\..\SHound\key.bin", myKey);
            File.WriteAllBytes(@"..\..\..\SHound\IV.bin", myIV);



        }


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
        static string PBytes(byte[] byteArray)
        {
            var sb = new StringBuilder("new byte[] { ");
            for (var i = 0; i < byteArray.Length; i++)
            {
                var b = byteArray[i];
                sb.Append(b);
                if (i < byteArray.Length - 1)
                {
                    sb.Append(", ");
                }
            }
            sb.Append(" }");
            return sb.ToString();
        }
    }
}