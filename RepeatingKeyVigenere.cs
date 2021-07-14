using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class RepeatingkeyVigenere : ICryptographicTechnique<string, string>
    {
        public string Analyse(string plainText, string cipherText)
        {
            string alphabets = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
            string lowerkeyAlphabets = alphabets.ToLower();
            int index = 0;
            int add = 0;
            char[,] vigenereTableau = new char[26, 26];
            string key = "";
            //build vigenere tableau
            for (int i = 0; i < 26; i++)
            {
                for (int j = 0; j < 26; j++)
                {
                    vigenereTableau[i, j] = alphabets[index];
                    index++;
                    if (index == 26)
                    {
                        index = 0;
                    }
                }
                add++;
                index = add;
                if (index == 26)
                {
                    index = add;
                }
            }
            //algorithm
            int col;
            int ind = 0;
            int count = 0;
            while (count != cipherText.Length)
            {
                col = lowerkeyAlphabets.IndexOf(plainText[ind]);
                for (int i = 0; i < 26; i++)
                {
                    if (cipherText[ind].Equals(vigenereTableau[i, col]))
                    {
                        key += lowerkeyAlphabets[i];
                        break;
                    }
                }
                count++;
                ind++;
            }
            int x = 0;
            string oneKey = "";
            bool d = false;
            while (!d)
            {
                if (x >= 3)
                {
                    if (key[x].Equals(oneKey[0]) && key[x + 1].Equals(oneKey[1]) && key[x + 2].Equals(oneKey[2]))
                    {
                        d = true;
                        break;
                    }
                }
                oneKey += key[x];
                x++;

            }
            return oneKey;
        }

        public string Decrypt(string cipherText, string key)
        {
            string alphabets = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
            string lowerkeyAlphabets = alphabets.ToLower();
            int index = 0;
            int add = 0;
            char[,] vigenereTableau = new char[26, 26];
            string plain = "";
            //build vigenere tableau
            for (int i = 0; i < 26; i++)
            {
                for (int j = 0; j < 26; j++)
                {
                    vigenereTableau[i, j] = alphabets[index];
                    index++;
                    if (index == 26)
                    {
                        index = 0;
                    }
                }
                add++;
                index = add;
                if (index == 26)
                {
                    index = add;
                }
            }

            //repeating the key
            int diff = cipherText.Length - key.Length;
            int index2 = 0;
            for (int i = 0; i < diff; i++)
            {
                key += key[index2];
                index2++;
            }
            //algorithm
            int col;
            int ind = 0;
            int count = 0;

            while (count != cipherText.Length)
            {
                col = lowerkeyAlphabets.IndexOf(key[ind]);
                for (int i = 0; i < 26; i++)
                {

                    if (cipherText[ind].Equals(vigenereTableau[i, col]))
                    {
                        plain += alphabets[i];
                    }
                }
                count++;
                ind++;
            }
            return plain;
        }

        public string Encrypt(string plainText, string key)
        {
            string alphabets = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
            string lowerkeyAlphabets = alphabets.ToLower();
            int index = 0;
            int add = 0;
            char[,] vigenereTableau = new char[26, 26];
            string cipher = "";
            //build vigenere tableau
            for (int i = 0; i < 26; i++)
            {
                for (int j = 0; j < 26; j++)
                {
                    vigenereTableau[i, j] = alphabets[index];
                    index++;
                    if (index == 26)
                    {
                        index = 0;
                    }
                }
                add++;
                index = add;
                if (index == 26)
                {
                    index = add;
                }
            }

            //repeating the key
            int diff = plainText.Length - key.Length;
            int index2 = 0;
            for (int i = 0; i < diff; i++)
            {
                key += key[index2];
                index2++;
            }

            //algorithm
            int row;
            int col;
            for (int i = 0; i < plainText.Length; i++)
            {
                row = lowerkeyAlphabets.IndexOf(plainText[i]);
                col = lowerkeyAlphabets.IndexOf(key[i]);
                cipher += vigenereTableau[row, col];
            }
            return cipher;
        }
    }
}