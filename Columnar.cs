using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class Columnar : ICryptographicTechnique<string, List<int>>
    {
        public List<int> Analyse(string plainText, string cipherText)
        {
            int firstCol = 0;
            int keySize = 0;
            char[,] finalMatrix = null;
            cipherText = cipherText.ToLower();
            plainText = plainText.ToLower();

            for (int k = 2; k < plainText.Length - 1; k++)
            {
                int numOfCol = k;
                double numOfRow = (double)plainText.Length / numOfCol;
                numOfRow = Math.Ceiling((double)numOfRow);
                char[,] matrix = new char[(int)numOfRow, numOfCol];
                int count = 0;

                for (int i = 0; i < numOfRow; i++)
                {
                    for (int j = 0; j < numOfCol; j++)
                    {
                        if (count == plainText.Length)
                            break;
                        matrix[i, j] = plainText[count];
                        count++;
                    }
                }
                string subStringK = cipherText.Substring(0, (int)numOfRow);
                count = 0;
                bool isTrue = true;

                for (int i = 0; i < numOfCol; i++)
                {
                    for (int j = 0; j < numOfRow; j++)
                    {
                        if (subStringK[j] != matrix[j, i])
                        {
                            isTrue = false;
                            break;
                        }
                        else
                            isTrue = true;
                    }
                    if (isTrue == true)
                    {
                        firstCol = i;
                        break;
                    }
                }
                if (isTrue == true)
                {
                    finalMatrix = matrix;
                    keySize = numOfCol;
                    break;
                }
            }
            double rowSize = (double)plainText.Length / keySize;
            rowSize = Math.Ceiling((double)rowSize);

            List<int> key = new List<int>(keySize);
            int[] keyArr = new int[keySize];
            keyArr[firstCol] = 1;
            int countCol = 2;

            for (int k = (int)rowSize; k < cipherText.Length - (int)rowSize - 1; k += (int)rowSize - 1)
            {
                bool isTrue = true;
                string subStringk = cipherText.Substring(k, (int)rowSize - 1);
                for (int i = 0; i < keySize; i++)
                {
                    for (int j = 0; j < rowSize - 1; j++)
                    {
                        if (subStringk[j] != finalMatrix[j, i])
                        {
                            isTrue = false;
                            break;
                        }
                        else
                            isTrue = true;
                    }
                    if (isTrue == true)
                    {
                        if (finalMatrix[(int)rowSize - 1, i] == cipherText[k + (int)rowSize - 1])
                            k++;
                        keyArr[i] = countCol;
                        countCol++;
                        break;
                    }
                }
            }
            key = keyArr.ToList();
            int endIndex = key.IndexOf(0);
            key[endIndex] = countCol;
            return key;
        }

        public string Decrypt(string cipherText, List<int> key)
        {
            string plainText = "";
            int numOfCol = key.Count;
            double numOfRow = (double)cipherText.Length / numOfCol;
            numOfRow = Math.Ceiling((double)numOfRow);
            char[,] matrix = new char[(int)numOfRow, numOfCol];
            int count = 0;

            for (int i = 0; i < numOfCol; i++)
            {
                for (int j = 0; j < numOfRow; j++)
                {
                    if (count == cipherText.Length)
                        break;
                    matrix[j, key.IndexOf(i + 1)] = cipherText[count];
                    count++;
                }
            }
            for (int i = 0; i < numOfRow; i++)
            {
                for (int j = 0; j < numOfCol; j++)
                {
                    plainText += matrix[i, j];
                }
            }
            return plainText;
        }

        public string Encrypt(string plainText, List<int> key)
        {
            string cipherText = "";
            int numOfCol = key.Count;
            double numOfRow = (double)plainText.Length / numOfCol;
            numOfRow = Math.Ceiling((double)numOfRow);
            char[,] matrix = new char[(int)numOfRow, numOfCol];
            int count = 0;
            for (int i = 0; i < numOfRow; i++)
            {
                for (int j = 0; j < numOfCol; j++)
                {
                    if (count == plainText.Length)
                    {
                        matrix[i, j] = 'x';
                    }
                    else
                    {
                        matrix[i, j] = plainText[count];
                        count++;
                    }
                }
            }
            for (int i = 0; i < numOfCol; i++)
            {
                for (int j = 0; j < numOfRow; j++)
                {
                    cipherText += matrix[j, key.IndexOf(i + 1)];
                }
            }
            return cipherText;
        }
    }
}
