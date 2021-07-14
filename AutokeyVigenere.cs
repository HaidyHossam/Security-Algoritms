using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class AutokeyVigenere : ICryptographicTechnique<string, string>
    {
        public string Analyse(string plainText, string cipherText)
        {
            string KeyStream = "";
            string Key = "";

            string alphabets = "abcdefghijklmnopqrstuvwxyz";
            string temp_alphabets = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";

            char[,] Matrix = new char[26, 26]; //rows for plain -- colomns for key
            for (int i = 0; i < 26; i++)
            {
                for (int j = 0; j < 26; j++)
                {
                    Matrix[i, j] = temp_alphabets[j];
                }
                char x = temp_alphabets[0];
                temp_alphabets = temp_alphabets.Substring(1);
                temp_alphabets += x;
            }

            for (int i = 0; i < plainText.Length; i++)
            {
                int IndexOfP = alphabets.IndexOf(plainText[i]);
                for (int j = 0; j < 26; j++)
                {
                    if (Matrix[IndexOfP, j] == cipherText[i])
                    {
                        KeyStream += alphabets[j];
                    }

                }
            }
            char p = plainText[0];
            bool stop = false;
            int k = 0, m = 0;

            while (stop != true)
            {
                if (KeyStream[k] != plainText[m])
                {
                    Key += KeyStream[k];
                }
                else
                {
                    if (plainText[m] + plainText[m + 1] == KeyStream[k] + KeyStream[k + 1])
                    {
                        stop = true;
                    }
                }
                k++;
            }
            return Key;
        }

        public string Decrypt(string cipherText, string key)
        {
            string alphabets = "abcdefghijklmnopqrstuvwxyz";
            string temp_alphabets = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";

            char[,] Matrix = new char[26, 26]; //rows for plain -- colomns for key
            for (int i = 0; i < 26; i++)
            {
                for (int j = 0; j < 26; j++)
                {
                    Matrix[i, j] = temp_alphabets[j];
                }
                char x = temp_alphabets[0];
                temp_alphabets = temp_alphabets.Substring(1);
                temp_alphabets += x;
            }

            string keyStream = key;
            string plain = "";
            int diff = cipherText.Length - key.Length;
            int count = 0;
            for (int i = 0; i < cipherText.Length; i++)
            {
                int IndexOfkey = alphabets.IndexOf(keyStream[i]);
                for (int j = 0; j < 26; j++)
                {
                    if (Matrix[j, IndexOfkey] == cipherText[i])
                    {
                        plain += alphabets[j];
                        if (count < diff)
                        {
                            keyStream += alphabets[j];
                            count++;
                        }
                    }

                }
            }
            return plain;
        }

        public string Encrypt(string plainText, string key)
        {
            string alphabets = "abcdefghijklmnopqrstuvwxyz";
            string temp_alphabets = alphabets;

            char[,] Matrix = new char[26, 26]; //rows for plain -- colomns for key
            for (int i = 0; i < 26; i++)
            {
                for (int j = 0; j < 26; j++)
                {
                    Matrix[i, j] = temp_alphabets[j];
                }
                char x = temp_alphabets[0];
                temp_alphabets = temp_alphabets.Substring(1);
                temp_alphabets += x;
            }
            string keyStream = key;
            string cipher = "";
            if (key.Length < plainText.Length)
            {
                int count = 0;
                for (int i = key.Length; i < plainText.Length; i++)
                {
                    keyStream += plainText[count];
                    count++;
                }
            }
            for (int i = 0; i < plainText.Length; i++)
            {
                int IndexOfplain = alphabets.IndexOf(plainText[i]);
                int IndexOfKey = alphabets.IndexOf(keyStream[i]);
                cipher += Matrix[IndexOfplain, IndexOfKey];
            }
            return cipher;
        }
    }
}
