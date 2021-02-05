using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace DiffieHellmanServer
{
    class Program
    {
        // Kalder krypterings klassen
        public static MyEncryption encryption = new MyEncryption();

        // De keys der bruges i diffie hellman, privkey er den private og pubserverkey er public
        public static string privKey = "webquiz";
        public static string pubServerKey = "pcandxlr";
        public static string combinedKey = pubServerKey + privKey;
        public static string newComboKey = "";

        // Laver en liste af tcpclients
        public static List<TcpClient> clients = new List<TcpClient>();
        static void Main(string[] args)
        {
            // Forbindelses informationer
            IPAddress ip = IPAddress.Parse("127.0.0.1");
            int port = 13356;

            // Starter og lytter til forbindelsen
            TcpListener listener = new TcpListener(ip, port);
            listener.Start();

            // Acceptere alle klienter der forsøger at tilgå serveren
            AcceptClients(listener);

            // Holder programmet kørende så vi kan sende krypterede beskeder frem og tilbage
            bool isRunning = true;
            while (isRunning)
            {
                // Skrive en besked
                Console.WriteLine("Write message: ");
                string text = Console.ReadLine();

                // Kryptere beskeden
                string encryptText = encryption.SubEncrypt(text, newComboKey);

                // Konvertere beskeden til bytes
                byte[] buffer = Encoding.UTF8.GetBytes(encryptText);

                // Afsender beskeden til alle klienter
                foreach (TcpClient client in clients)
                {
                    client.GetStream().Write(buffer, 0, buffer.Length);
                }
            }
        }

        public static async void AcceptClients(TcpListener listener)
        {
            // Holder den asynkrone funktion kørende og acceptere alle afventende klienter
            bool isRunning = true;
            while (isRunning)
            {
                // Opretter en klient som indeholder den accepterede klient i køen og tilføjer klienten til klient listen
                TcpClient client = await listener.AcceptTcpClientAsync();
                clients.Add(client);

                // Laver en kombineret privat og delt nøgle til diffie hellman
                byte[] keyBuffer = Encoding.UTF8.GetBytes(combinedKey);

                // Opretter en netværksstrøm der er tilhørende klienten
                NetworkStream stream = client.GetStream();
                ReceiveMessages(stream);

                // Sender server nøglen
                stream.Write(keyBuffer, 0, keyBuffer.Length);
            }
        }

        public static async void ReceiveMessages(NetworkStream stream)
        {
            // Opretter en buffer
            byte[] buffer = new byte[256];

            // Holder programmet kørende mens det modtager kommende beskeder
            bool isRunning = true;
            while (isRunning)
            {
                // Indlæser den kommende buffer asynkront
                int read = await stream.ReadAsync(buffer, 0, buffer.Length);

                // Konvertere den in kommende buffer til tekst
                string text = Encoding.UTF8.GetString(buffer, 0, read);

                // Hvis ikke beskeden indeholder klientens public key til sidst skal den dekrypteres og printes
                if (!text.EndsWith("pcandxlr"))
                {
                    // Print og dekrypter beskeden print indeholder både krypteret og ukrypteret kontrol besked
                    Console.WriteLine("client writes encrypted: " + text);
                    string decryptText = encryption.SubDecrypt(text, newComboKey);
                    Console.WriteLine("client writes decrypted: " + decryptText);
                } 
                else
                {
                    // Samle diffie hellman nøglen og print den ud som kontrol
                    newComboKey = text + privKey;
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
