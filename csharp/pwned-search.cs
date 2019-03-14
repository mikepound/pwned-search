using System;
using System.Security.Cryptography;
using System.Text;
using System.Net;
using System.IO;

namespace pwned_search {
    class Program {
        static void Main(string[] args) {
            Console.Write("Enter the password to check: ");
            string plaintext = Console.ReadLine();

            SHA1 sha = new SHA1CryptoServiceProvider();
            byte[] data = sha.ComputeHash(Encoding.ASCII.GetBytes(plaintext));

            // Loop through each byte of the hashed data 
            // and format each one as a hexadecimal string.
            var sBuilder = new StringBuilder();
            for (int i = 0; i < data.Length; i++) {
                sBuilder.Append(data[i].ToString("x2"));
            }
            string result = sBuilder.ToString().ToUpper();
            Console.WriteLine($"The SHA-1 hash of {plaintext} is: {result}");

            // get a list of all the possible passwords where the first 5 digits of the hash are the same
            string url = "https://api.pwnedpasswords.com/range/" + result.Substring(0, 5);
            WebRequest request= WebRequest.Create(url);
            Stream response = request.GetResponse().GetResponseStream();
            StreamReader reader = new StreamReader(response);

            // look at each possibility and compare the rest of the hash to see if there is a match
            string hashToCheck = result.Substring(5);
            while (true) {
                string line = reader.ReadLine();
                if (line == null) {
                    Console.WriteLine("That password was not found.");
                    break;
                }
                string[] parts = line.Split(':');
                if (parts[0] == hashToCheck) {
                    Console.WriteLine("Password has been compromised -- DO NOT USE!");
                    break;
                }
            }
            
            Console.ReadKey(); // pause until key press
        }
    }
}
