using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace DiffieHellmanClient
{
    class Program
    {
        // Kalder krypterings klassen
        public static MyEncryption encryption = new MyEncryption();

        // De keys der bruges i diffie hellman, privkey er den private og pubserverkey er public
        public static string privKey = "jfkgotmyvhs";
        public static string pubClientKey = "pcandxlr";
        public static string combinedKey = privKey + pubClientKey;
        public static string newComboKey = "";

        static void Main(string[] args)
        {
            // Opretter en tcpclient
            TcpClient client = new TcpClient();

            // Forbindelses informationer
            IPAddress ip = IPAddress.Parse("127.0.0.1");
            int port = 13356;

            // Forbinder til serveren
            IPEndPoint endPoint = new IPEndPoint(ip, port);
            client.Connect(endPoint);

            // Laver en kombineret privat og delt nøgle til diffie hellman
            byte[] keyBuffer = Encoding.UTF8.GetBytes(combinedKey);

            // Opretter en netværksstrøm der er tilhørende klienten
            NetworkStream stream = client.GetStream();
            RecieveMessage(stream);

            // Sender klient nøglen
            stream.Write(keyBuffer, 0, keyBuffer.Length);

            // Skrive en besked
            Console.WriteLine("Write your message here: ");
            string text = Console.ReadLine();

            // Kryptere beskeden
            string encryptText = encryption.SubEncrypt(text, newComboKey);

            // Konvertere beskeden til bytes
            byte[] buffer = Encoding.UTF8.GetBytes(encryptText);

            // Afsender beskeden til serveren
            stream.Write(buffer, 0, buffer.Length);

            // Pause til vilkårlig tast er trykket
            Console.ReadKey();
        }

        static async void RecieveMessage(NetworkStream stream)
        {
            // Opretter en buffer
            byte[] buffer = new byte[256];

            // Holder programmet kørende mens det modtager kommende beskeder
            bool isRunning = true;
            while (isRunning)
            {
                // Indlæser den kommende buffer asynkront
                int numberOfBytesRead = await stream.ReadAsync(buffer, 0, buffer.Length);

                // Konvertere den in kommende buffer til tekst
                string receivedMessage = Encoding.UTF8.GetString(buffer, 0, numberOfBytesRead);

                // Hvis ikke beskeden indeholder serverens public key til sidst skal den dekrypteres og printes
                if (!receivedMessage.StartsWith("pcandxlr"))
                {
                    // Print og dekrypter beskeden print indeholder både krypteret og ukrypteret kontrol besked
                    Console.WriteLine(receivedMessage);
                    string decryptText = encryption.SubDecrypt(receivedMessage, newComboKey);
                    Console.WriteLine(decryptText);
                }
                else
                {
                    // Samle diffie hellman nøglen og print den ud som kontrol
                    newComboKey = privKey + receivedMessage;
                    Console.WriteLine("Combined key: " + newComboKey);
                }
            }
        }
    }
    public class MyEncryption
    {
        // Krypterings metode substitution
        public string SubEncrypt(string plainText, string key)
        {
            // Opretter et chararray på længden af beskeden
            char[] chars = new char[plainText.Length];

            // For hver char i arrayet
            for (int i = 0; i < plainText.Length; i++)
            {
                if (plainText[i] == ' ')
                {
                    // Hvis mellemrum indsæt mellemrum
                    chars[i] = ' ';
                }
                else
                {
                    // Ellers ændre værdien med -97 og indsæt værdien
                    int j = plainText[i] - 97;
                    chars[i] = key[j];
                }
            }

            // Returner beskeden 
            return new string(chars);
        }

        // Dekrypterings metode substitution
        public string SubDecrypt(string cipherText, string key)
        {
            // Opretter et chararray på længden af beskeden
            char[] chars = new char[cipherText.Length];

            // For hver char i arrayet
            for (int i = 0; i < cipherText.Length; i++)
            {
                if (cipherText[i] == ' ')
                {
                    // Hvis mellemrum indsæt mellemrum
                    chars[i] = ' ';
                }
                else
                {
                    // Ellers ændre værdien med +97 og indsæt værdien
                    int j = key.IndexOf(cipherText[i]) + 97;
                    chars[i] = (char)j;
                }
            }

            // Returner beskeden 
            return new string(chars);
        }
    }
}
