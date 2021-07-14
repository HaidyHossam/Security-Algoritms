using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class RailFence : ICryptographicTechnique<string, int>
    {
        public int Analyse(string plainText, string cipherText)
        {
            int depth = 0;
            cipherText = cipherText.ToLower();
            plainText = plainText.ToLower();

            for (int k = 2; k < plainText.Length - 1; k++)
            {
                int numOfRow = k;
                double numOfCol = (double)plainText.Length / numOfRow;
                numOfCol = Math.Ceiling((double)numOfCol);
                char[,] matrix = new char[numOfRow, (int)numOfCol];
                int count = 0;

                for (int i = 0; i < numOfCol; i++)
                {
                    for (int j = 0; j < numOfRow; j++)
                    {
                        if (count == plainText.Length)
                            break;
                        matrix[j, i] = plainText[count];
                        count++;
                    }
                }
                string subStringK = cipherText.Substring(0, (int)numOfCol);
                count = 0;
                bool isTrue = true;

                for (int i = 0; i < numOfRow; i++)
                {
                    for (int j = 0; j < numOfCol; j++)
                    {
                        if (subStringK[j] != matrix[i, j])
                        {
                            isTrue = false;
                            break;
                        }
                        else
                            isTrue = true;
                    }
                    if (isTrue == true)
                    {
                        break;
                    }
                }
                if (isTrue == true)
                {
                    depth = (int)numOfRow;
                    break;
                }
            }
            return depth;
        }

        public string Decrypt(string cipherText, int key)
        {
            cipherText = cipherText.ToLower();
            decimal DivRes = Convert.ToDecimal(cipherText.Count()) / Convert.ToDecimal(key);
            decimal Num = Math.Ceiling(DivRes);
            int IntNum = Convert.ToInt32(Num);
            char[,] array = new char[key, IntNum];
            int Counter = 0;
            char[] TempArr = new char[50];

            for (int i = 0; i < key; i++)
            {
                for (int j = 0; j < IntNum; j++)
                {
                    array[i, j] = cipherText[Counter];
                    Counter++;
                    if (Counter >= cipherText.Count())
                    {
                        break;
                    }
                }
            }

            Counter = 0;
            for (int i = 0; i < IntNum; i++)
            {
                for (int j = 0; j < key; j++)
                {
                    TempArr[Counter] = array[j, i];
                    Counter++;
                }
            }

            string plainText = new string(TempArr);
            plainText = plainText.Substring(0, cipherText.Count());
            return plainText;
        }

        public string Encrypt(string plainText, int key)
        {
            char[] TempArr = new char[50];
            int Counter = 0;
            decimal DivRes = Convert.ToDecimal(plainText.Count()) / Convert.ToDecimal(key);
            decimal Num = Math.Ceiling(DivRes);
            int IntNum = Convert.ToInt32(Num);
            char[,] array = new char[key, IntNum];

            for (int j = 0; j < IntNum; j++)
            {
                for (int i = 0; i < key; i++)
                {
                    if (Counter >= plainText.Count())
                    {
                        array[i, j] = 'x';
                    }
                    else
                    {
                        array[i, j] = plainText[Counter];
                        Counter++;
                    }
                }
            }

            Counter = 0;
            for (int i = 0; i < key; i++)
            {
                for (int j = 0; j < IntNum; j++)
                {
                    if (array[i, j] == 'x')
                    {
                        continue;
                    }
                    else
                    {
                        TempArr[Counter] = array[i, j];
                        Counter++;
                    }
                }
            }

            string CipherText = new string(TempArr);
            CipherText = CipherText.Substring(0, plainText.Count());
            return CipherText;
        }
    }
}
