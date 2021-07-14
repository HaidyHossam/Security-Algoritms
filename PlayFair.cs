using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class PlayFair : ICryptographic_Technique<string, string>
    {
        public int[] findIndex(char[,] matrix, char value)
        {
            int[] index = new int[2];
            for (int i = 0; i < 5; i++)
            {
                for (int j = 0; j < 5; j++)
                {
                    if (matrix[i, j] == value)
                    {
                        index[0] = i;
                        index[1] = j;
                        break;
                    }
                }
            }
            return index;
        }
        public char[,] createKeyMatrix(string key, string plainText)
        {
            string alphabet = "ABCDEFGHIKLMNOPQRSTUVWXYZ";
            string newKey = "";
            int alphabetCount = 0;
            string clearedAlphabet = "";
            char[,] keyMartix = new char[5, 5];
            int l = 0, w = 0;

            key = key.ToUpper();
            key = key.Replace('J', 'I');

            for (int i = 0; i < key.Length; i++)
            {
                if (!newKey.Contains(key[i]))
                    newKey += key[i];
            }
            for (int k = 0; k < newKey.Length; k++)
            {
                keyMartix[l, w] = newKey[k];
                w++;
                if (w == 5)
                {
                    l++;
                    w = 0;
                }
            }

            for (int i = 0; i < alphabet.Length; i++)
            {
                if (!newKey.Contains(alphabet[i]))
                    clearedAlphabet += alphabet[i];
            }
            if (clearedAlphabet.Length != 0)
            {
                for (int j = w; j < 5; j++)
                {
                    keyMartix[l, j] = clearedAlphabet[alphabetCount];
                    alphabetCount++;
                }
                for (int i = l + 1; i < 5; i++)
                {
                    for (int j = 0; j < 5; j++)
                    {
                        keyMartix[i, j] = clearedAlphabet[alphabetCount];
                        alphabetCount++;
                    }
                }
            }
            return keyMartix;
        }
        public string Decrypt(string cipherText, string key)
        {
            cipherText = cipherText.ToUpper();
            key = key.ToUpper();
            char[,] keyMartix = createKeyMatrix(key, cipherText);
            string plainText = "";
            
            for (int i = 0; i < cipherText.Length; i += 2)
            {
                int[] charIndex = findIndex(keyMartix, cipherText[i]);
                int[] charIndex2 = findIndex(keyMartix, cipherText[i + 1]);
                if (cipherText[i] == cipherText[i + 1])
                {
                    cipherText = cipherText.Insert(i + 1, "X");
                    charIndex2 = findIndex(keyMartix, 'X');
                }
                if (charIndex[0] == charIndex2[0])
                {
                    if (charIndex[1] == 0)
                    {
                        plainText += keyMartix[charIndex[0], 4];
                        plainText += keyMartix[charIndex2[0], charIndex2[1] - 1];
                    }
                    else if (charIndex2[1] == 0)
                    {
                        plainText += keyMartix[charIndex[0], charIndex[1] - 1];
                        plainText += keyMartix[charIndex2[0], 4];
                    }
                    else
                    {
                        plainText += keyMartix[charIndex[0], charIndex[1] - 1];
                        plainText += keyMartix[charIndex2[0], charIndex2[1] - 1];
                    }
                }

                else if (charIndex[1] == charIndex2[1])
                {
                    if (charIndex[0] == 0)
                    {
                        plainText += keyMartix[4, charIndex[1]];
                        plainText += keyMartix[charIndex2[0] - 1, charIndex[1]];
                    }
                    else if (charIndex2[0] == 0)
                    {
                        plainText += keyMartix[charIndex[0] - 1, charIndex[1]];
                        plainText += keyMartix[4, charIndex[1]];
                    }
                    else
                    {
                        plainText += keyMartix[charIndex[0] - 1, charIndex[1]];
                        plainText += keyMartix[charIndex2[0] - 1, charIndex[1]];
                    }
                }
                else
                {
                    plainText += keyMartix[charIndex[0], charIndex2[1]];
                    plainText += keyMartix[charIndex2[0], charIndex[1]];
                }
            }
            string newPlain = "";
            for (int i = 0; i < plainText.Length - 1; i += 2)
            {
                if (plainText[i + 1] == 'X' && i < plainText.Length - 2 && plainText[i] == plainText[i + 2])
                    newPlain += plainText[i];
                else
                {
                    newPlain += plainText[i];
                    newPlain += plainText[i + 1];
                }
            }

            if (newPlain[newPlain.Length - 1] == 'X')
                newPlain = newPlain.Remove(newPlain.Length - 1, 1);
            return newPlain;
        }

        public string Encrypt(string plainText, string key)
        {
            plainText = plainText.ToUpper();
            key = key.ToUpper();
            char[,] keyMartix = createKeyMatrix(key, plainText);
            string cipherText = "";

            for (int i = 0; i < plainText.Length; i += 2)
            {
                if (i == plainText.Length - 1 && plainText.Length % 2 != 0)
                    plainText = plainText.Insert(plainText.Length, "X");
                int[] charIndex = findIndex(keyMartix, plainText[i]);
                int[] charIndex2 = findIndex(keyMartix, plainText[i + 1]);
                if (plainText[i] == plainText[i + 1])
                {
                    plainText = plainText.Insert(i + 1, "X");
                    charIndex2 = findIndex(keyMartix, 'X');
                }
                if (charIndex[0] == charIndex2[0])
                {
                    if (charIndex[1] == 4)
                    {
                        cipherText += keyMartix[charIndex[0], 0];
                        cipherText += keyMartix[charIndex2[0], charIndex2[1] + 1];
                    }
                    else if (charIndex2[1] == 4)
                    {
                        cipherText += keyMartix[charIndex[0], charIndex[1] + 1];
                        cipherText += keyMartix[charIndex2[0], 0];
                    }
                    else
                    {
                        cipherText += keyMartix[charIndex[0], charIndex[1] + 1];
                        cipherText += keyMartix[charIndex2[0], charIndex2[1] + 1];
                    }
                }

                else if (charIndex[1] == charIndex2[1])
                {
                    if (charIndex[0] == 4)
                    {
                        cipherText += keyMartix[0, charIndex[1]];
                        cipherText += keyMartix[charIndex2[0] + 1, charIndex[1]];
                    }
                    else if (charIndex2[0] == 4)
                    {
                        cipherText += keyMartix[charIndex[0] + 1, charIndex[1]];
                        cipherText += keyMartix[0, charIndex[1]];
                    }
                    else
                    {
                        cipherText += keyMartix[charIndex[0] + 1, charIndex[1]];
                        cipherText += keyMartix[charIndex2[0] + 1, charIndex[1]];
                    }
                }
                else
                {
                    cipherText += keyMartix[charIndex[0], charIndex2[1]];
                    cipherText += keyMartix[charIndex2[0], charIndex[1]];
                }
            }
            return cipherText;
        }
    }
}
