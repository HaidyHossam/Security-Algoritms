using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class Monoalphabetic : ICryptographicTechnique<string, string>
    {
        public string Analyse(string plainText, string cipherText)
        {
            string PlainText = plainText.ToLower();
            string CipherText = cipherText.ToLower();
            char[] Alphabetic = new char[26];
            char[] TempKey = new char[26];
            char[] FreeChars = new char[26];
            char Char_Start = 'a';
            int Counter = 0;
            int Counter2 = 0;
            bool isExist = false;

            for (int i = 0; i < 26; i++)
            {
                Alphabetic[i] = Char_Start;
                Char_Start++;
            }

            for (int i = 0; i < 26; i++)
            {
                TempKey[i] = '$';
            }

            for (int i = 0; i < PlainText.Count(); i++)
            {
                for (int j = 0; j < Alphabetic.Count(); j++)
                {
                    if (PlainText[i] == Alphabetic[j])
                    {
                        TempKey[j] = CipherText[i];
                        break;
                    }
                }
            }

            for (int i = 0; i < Alphabetic.Count(); i++)
            {
                for (int j = 0; j < CipherText.Count(); j++)
                {
                    if (Alphabetic[i] != CipherText[j])
                    {
                        isExist = false;
                    }
                    else
                    {
                        isExist = true;
                        break;
                    }
                }
                if (isExist == false)
                {
                    FreeChars[Counter] = Alphabetic[i];
                    Counter++;
                }
            }

            for (int i = 0; i < TempKey.Count(); i++)
            {
                if (TempKey[i] == '$')
                {
                    TempKey[i] = FreeChars[Counter2];
                    Counter2++;
                }
            }

            string Key = new string(TempKey);
            return Key;
        }

        public string Decrypt(string cipherText, string key)
        {
            char[,] keyArr = new char[26, 2];


            char start = 'a';
            string keyUpper = key.ToUpper();

            char[] cipherTextArr = cipherText.ToCharArray();
            char[] plainTextArr = new char[cipherText.Length];

            for (int i = 0; i < 26; i++)     //fill 2d key array
            {
                keyArr[i, 0] = start;
                start++;
                keyArr[i, 1] = keyUpper[i];
            }

            int count = 0;
            int count2 = 0;
            int index = 0;

            while (count2 != cipherText.Length)      //monoalphabetic algorithm
            {
                for (int i = 0; i < 26; i++)
                {
                    if (cipherTextArr[count].Equals(keyArr[i, 1]))
                    {
                        plainTextArr[index] = keyArr[i, 0];
                        index++;
                    }
                }
                count++;
                count2++;
            }
            string plainText = new string(plainTextArr);
            return plainText;
        }

        public string Encrypt(string plainText, string key)
        {
            char[,] keyArr = new char[26, 2];


            char start = 'a';
            char[] plainTextArr = plainText.ToCharArray();
            char[] cipherArr = new char[plainText.Length];

            for (int i = 0; i < 26; i++)     //fill 2d key array
            {
                keyArr[i, 0] = start;
                start++;
                keyArr[i, 1] = key[i];
            }

            int count = 0;
            int count2 = 0;
            int index = 0;
            while (count2 != plainText.Length)      //monoalphabetic algorithm
            {
                for (int i = 0; i < 26; i++)
                {
                    if (plainTextArr[count].Equals(keyArr[i, 0]))
                    {
                        cipherArr[index] = keyArr[i, 1];
                        index++;
                    }
                }
                count++;
                count2++;
            }
            string cipher = new string(cipherArr);
            return cipher;
        }

        /// <summary>
        /// Frequency Information:
        /// E   12.51%
        /// T	9.25
        /// A	8.04
        /// O	7.60
        /// I	7.26
        /// N	7.09
        /// S	6.54
        /// R	6.12
        /// H	5.49
        /// L	4.14
        /// D	3.99
        /// C	3.06
        /// U	2.71
        /// M	2.53
        /// F	2.30
        /// P	2.00
        /// G	1.96
        /// W	1.92
        /// Y	1.73
        /// B	1.54
        /// V	0.99
        /// K	0.67
        /// X	0.19
        /// J	0.16
        /// Q	0.11
        /// Z	0.09
        /// </summary>
        /// <param name="cipher"></param>
        /// <returns>Plain text</returns>
        public string AnalyseUsingCharFrequency(string cipher)
        {
            Dictionary<char, double> Frequencies = new Dictionary<char, double>();
            Frequencies.Add('e', 12.51);
            Frequencies.Add('t', 9.25);
            Frequencies.Add('a', 8.04);
            Frequencies.Add('o', 7.60);
            Frequencies.Add('i', 7.26);
            Frequencies.Add('n', 7.09);
            Frequencies.Add('s', 6.54);
            Frequencies.Add('r', 6.12);
            Frequencies.Add('h', 5.49);
            Frequencies.Add('l', 4.14);
            Frequencies.Add('d', 3.99);
            Frequencies.Add('c', 3.06);
            Frequencies.Add('u', 2.71);
            Frequencies.Add('m', 2.53);
            Frequencies.Add('f', 2.30);
            Frequencies.Add('p', 2.00);
            Frequencies.Add('g', 1.96);
            Frequencies.Add('w', 1.92);
            Frequencies.Add('y', 1.73);
            Frequencies.Add('b', 1.54);
            Frequencies.Add('v', 0.99);
            Frequencies.Add('k', 0.67);
            Frequencies.Add('x', 0.19);
            Frequencies.Add('j', 0.16);
            Frequencies.Add('q', 0.11);
            Frequencies.Add('z', 0.09);

            string tmp_cipher = cipher;
            Dictionary<char, double> Cipher_freqs = new Dictionary<char, double>();
            for (int i = 0; i < tmp_cipher.Length; i++)
            {
                int count = 1;
                for (int j = i + 1; j < tmp_cipher.Length; j++)
                {
                    if (tmp_cipher[j] == tmp_cipher[i])
                    {
                        count++;
                    }
                }

                if (!Cipher_freqs.ContainsKey(tmp_cipher[i]))
                {
                    Cipher_freqs.Add(tmp_cipher[i], count);
                }
            }

            Dictionary<char, double> sortedDict = new Dictionary<char, double>();
            var items = from pair in Cipher_freqs
                        orderby pair.Value descending
                        select pair;
            foreach (KeyValuePair<char, double> pair in items)
            {
                sortedDict.Add(pair.Key, pair.Value);
            }
            string plain = "";
            for (int i = 0; i < cipher.Length; i++)
            {
                int index = 0;
                char element;
                for (int j = 0; j < sortedDict.Count(); j++)
                {
                    if (cipher[i] == sortedDict.ElementAt(j).Key)
                    {
                        index = j;
                        element = Frequencies.ElementAt(index).Key;
                        plain += element;
                    }

                }
            }
            return plain;
        }
    }
}
