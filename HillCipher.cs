using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    /// <summary>
    /// The List<int> is row based. Which means that the key is given in row based manner.
    /// </summary>
    public class HillCipher :  ICryptographicTechnique<List<int>, List<int>>
    {
        public int gcd(int n1, int n2)
        {
            if (n2 == 0)
            {
                return n1;
            }
            else
            {
                return gcd(n2, n1 % n2);
            }
        }
        public int[,] getInverse(int[,] miniMatrix)
        {
            int[,] matrixInverse = new int[2, 2];
            int detValue = ((miniMatrix[0, 0] * miniMatrix[1, 1]) -
                (miniMatrix[0, 1] * miniMatrix[1, 0])) % 26;
            int x = 0;
            for (int i = 1; i < 26; i++)
            {
                if (((detValue * i) % 26) == 1)
                {
                    x = i;
                    break;
                }
            }
            matrixInverse[0, 0] = ((miniMatrix[1, 1] % 26) * x) % 26;
            matrixInverse[0, 1] = (((((-1 * miniMatrix[0, 1]) % 26) + 26) % 26) * x) % 26;
            matrixInverse[1, 0] = (((((-1 * miniMatrix[1, 0]) % 26) + 26) % 26) * x) % 26;
            matrixInverse[1, 1] = (miniMatrix[0, 0] % 26 * x) % 26;

            return matrixInverse;
        }
        public int calDet(int[,] miniMatrix)
        {
            int detValue = (miniMatrix[0, 0] * miniMatrix[1, 1]) -
                (miniMatrix[0, 1] * miniMatrix[1, 0]);
            return detValue;
        }
        public List<int> Analyse(List<int> plainText, List<int> cipherText)
        {
            List<int> key = new List<int>();
            int matrixSize = plainText.Count / 2;
            int[,] matrixPlain = new int[2,matrixSize];
            int[,] matrixCipher = new int[2, matrixSize];
            int[,] miniplain = new int[2, 2];
            int[,] minicipher = new int[2, 2];
            int[,] keyMatrix = new int[2, 2];
            int iter = 0;
            int col1 = 0, col2 = 1;
            bool inverseExist = false;

            for (int i = 0; i < matrixSize; i++)
            {
                for (int j = 0; j < 2; j++)
                {
                    matrixPlain[j, i] = plainText[iter];
                    iter++;
                }
            }
            iter = 0;
            for (int i = 0; i < matrixSize; i++)
            {
                for (int j = 0; j < 2; j++)
                {
                    matrixCipher[j, i] = cipherText[iter];
                    iter++;
                }
            }
            for (int i = 0; i < matrixSize; i++)
            {
                int[,] miniMatrix = new int[2, 2];
                int detValue;
                if (i == matrixSize - 1)
                {
                    miniMatrix[0, 0] = matrixPlain[0, i - 1];
                    miniMatrix[0, 1] = matrixPlain[1, i - 1];
                    miniMatrix[1, 0] = matrixPlain[0, i];
                    miniMatrix[1, 1] = matrixPlain[1, i];
                    detValue = calDet(miniMatrix);
                    if (gcd(detValue, 26) == 1)
                    {
                        col1 = i - 1;
                        col2 = i;
                        inverseExist = true;
                        break;
                    }
                }
                else
                {
                    for (int k = i + 1; k < matrixSize; k++)
                    {
                        miniMatrix[0, 0] = matrixPlain[0, i];
                        miniMatrix[0, 1] = matrixPlain[0, k];
                        miniMatrix[1, 0] = matrixPlain[1, i];
                        miniMatrix[1, 1] = matrixPlain[1, k];
                        detValue = calDet(miniMatrix);
                        if (gcd(detValue, 26) == 1)
                        {
                            col1 = i;
                            col2 = k;
                            inverseExist = true;
                            break;
                        }
                    }
                }
            }
            if(inverseExist == false)
            {
                throw (new InvalidAnlysisException());
            }

            miniplain[0, 0] = matrixPlain[0, col1];
            miniplain[0, 1] = matrixPlain[0, col2];
            miniplain[1, 0] = matrixPlain[1, col1];
            miniplain[1, 1] = matrixPlain[1, col2];

            minicipher[0, 0] = matrixCipher[0, col1];
            minicipher[0, 1] = matrixCipher[0, col2];
            minicipher[1, 0] = matrixCipher[1, col1];
            minicipher[1, 1] = matrixCipher[1, col2];

            keyMatrix = getInverse(miniplain);

            key.Add(((minicipher[0, 0] * keyMatrix[0, 0]) + (minicipher[0, 1] * keyMatrix[1, 0])) % 26);
            key.Add(((minicipher[0, 0] * keyMatrix[0, 1]) + (minicipher[0, 1] * keyMatrix[1, 1])) % 26);
            key.Add(((minicipher[1, 0] * keyMatrix[0, 0]) + (minicipher[1, 1] * keyMatrix[1, 0])) % 26);
            key.Add(((minicipher[1, 0] * keyMatrix[0, 1]) + (minicipher[1, 1] * keyMatrix[1, 1])) % 26);

            return key;
        }


        public List<int> Decrypt(List<int> cipherText, List<int> key)
        {
            int m;
            List<int> Plain = new List<int>();//output list
            m = Convert.ToInt32(Math.Sqrt(key.Count));

            int[,] keymatrix = new int[m, m];
            double[,] tempkeyInverse = new double[m, m];   //multi_inverse * sub matrices of key 
            double[,] keyInverse = new double[m, m];

            int count = 0;//to get the key list
            double multi_inverse = 0;//multiplicative inverse 
            //convert key list to matrix to deal with it easer 
            for (int col = 0; col < m; col++)
            {
                for (int row = 0; row < m; row++)
                {
                    keymatrix[row, col] = key[count];
                    count++;
                }
            }

            if (m == 2)
            {
                int detValue = (((((keymatrix[0, 0] * keymatrix[1, 1]) - keymatrix[1, 0] * keymatrix[0, 1]) % 26) +26) % 26);
                if (gcd(detValue, 26) != 1)
                {
                    throw (new Exception());
                }
                multi_inverse = 1 / ((keymatrix[0, 0] * keymatrix[1, 1]) - keymatrix[1, 0] * keymatrix[0, 1]);


                keyInverse[0, 0] = (multi_inverse * keymatrix[1, 1]) % 26;
                if (keyInverse[0, 0] < 0)
                    keyInverse[0, 0] += 26;

                keyInverse[1, 1] = (multi_inverse * keymatrix[0, 0]) % 26;
                if (keyInverse[1, 1] < 0)
                    keyInverse[1, 1] += 26;

                keyInverse[1, 0] = (multi_inverse * (-keymatrix[1, 0])) % 26;
                if (keyInverse[1, 0] < 0)
                    keyInverse[1, 0] += 26;

                keyInverse[0, 1] = (multi_inverse * (-keymatrix[0, 1])) % 26;
                if (keyInverse[0, 1] < 0)
                    keyInverse[0, 1] += 26;


                List<int> templist1;
                List<int> outputTempList1 = new List<int>();
                int count1 = cipherText.Count;

                for (int i = 0; i <= count1; i++)
                {
                    templist1 = cipherText.GetRange(0, m);
                    //process the temp list and add it to cipher list
                    for (int j = 0; j < m; j++)
                    {
                        int num = 0;
                        for (int row = 0; row < m; row++)
                        {
                            int n = num;
                            num = (Convert.ToInt32(keyInverse[row, j]) * templist1[row]);
                            num = n + num;
                        }
                        outputTempList1.Add(num % 26);
                    }
                    templist1.Clear();
                    cipherText.RemoveRange(0, m);

                    if (cipherText.Count == 0)
                    {
                        break;
                    }
                }
                return outputTempList1;
            }
            else//m=3
            {
                //get det(k)
                int det = 0;
                det = (keymatrix[0, 0] * (keymatrix[1, 1] * keymatrix[2, 2] - keymatrix[1, 2] * keymatrix[2, 1])) - (keymatrix[1, 0] * (keymatrix[0, 1] * keymatrix[2, 2] - keymatrix[0, 2] * keymatrix[2, 1])) + keymatrix[2, 0] * (keymatrix[0, 1] * keymatrix[1, 2] - keymatrix[0, 2] * keymatrix[1, 1]);
                det %= 26;
                if (det < 0)
                    det += 26;
                //getting multi_inverse
                int[] q = new int[100];
                int[] A1 = new int[100];
                int[] A2 = new int[100];
                int[] A3 = new int[100];
                int[] B1 = new int[100];
                int[] B2 = new int[100];
                int[] B3 = new int[100];

                q[0] = 0;
                A1[0] = 1;
                A2[0] = 0;
                A3[0] = 26;
                B1[0] = 0;
                B2[0] = 1;
                B3[0] = det;
                int index = 1;
                while (index != 100)
                {
                    q[index] = A3[index - 1] / B3[index - 1];
                    A1[index] = B1[index - 1];
                    A2[index] = B2[index - 1];

                    A3[index] = B3[index - 1];
                    B3[index] = A3[index - 1] - (B3[index - 1] * q[index]);
                    B1[index] = A1[index - 1] - (q[index] * B1[index - 1]);
                    B2[index] = A2[index - 1] - (q[index] * B2[index - 1]);

                    if (B3[index] == 1)
                    {
                        multi_inverse = (B2[index] % 26);
                        if (multi_inverse < 0)
                            multi_inverse += 26;
                        break;
                    }
                    if (B3[index] == 0)
                    {
                        multi_inverse = B2[index];
                        break;
                    }
                    index++;
                }
                //multi_inverse * sub matrices of key 

                tempkeyInverse[0, 0] = (multi_inverse * ((keymatrix[1, 1] * keymatrix[2, 2]) - (keymatrix[2, 1] * keymatrix[1, 2]))) % 26;
                if (tempkeyInverse[0, 0] < 0)
                    tempkeyInverse[0, 0] += 26;

                tempkeyInverse[1, 0] = (multi_inverse * (-((keymatrix[0, 1] * keymatrix[2, 2]) - (keymatrix[2, 1] * keymatrix[0, 2])))) % 26;
                if (tempkeyInverse[1, 0] < 0)
                    tempkeyInverse[1, 0] += 26;

                tempkeyInverse[2, 0] = (multi_inverse * (((keymatrix[0, 1] * keymatrix[1, 2]) - (keymatrix[1, 1] * keymatrix[0, 2])))) % 26;
                if (tempkeyInverse[2, 0] < 0)
                    tempkeyInverse[2, 0] += 26;

                tempkeyInverse[0, 1] = (multi_inverse * (-((keymatrix[1, 0] * keymatrix[2, 2]) - (keymatrix[1, 2] * keymatrix[2, 0])))) % 26;
                if (tempkeyInverse[0, 1] < 0)
                    tempkeyInverse[0, 1] += 26;

                tempkeyInverse[1, 1] = (multi_inverse * (((keymatrix[0, 0] * keymatrix[2, 2]) - (keymatrix[0, 2] * keymatrix[2, 0])))) % 26;
                if (tempkeyInverse[1, 1] < 0)
                    tempkeyInverse[1, 1] += 26;

                tempkeyInverse[2, 1] = (multi_inverse * (-((keymatrix[0, 0] * keymatrix[1, 2]) - (keymatrix[0, 2] * keymatrix[1, 0])))) % 26;
                if (tempkeyInverse[2, 1] < 0)
                    tempkeyInverse[2, 1] += 26;

                tempkeyInverse[0, 2] = (multi_inverse * (((keymatrix[1, 0] * keymatrix[2, 1]) - (keymatrix[2, 0] * keymatrix[1, 1])))) % 26;
                if (tempkeyInverse[0, 2] < 0)
                    tempkeyInverse[0, 2] += 26;

                tempkeyInverse[1, 2] = (multi_inverse * (-((keymatrix[0, 0] * keymatrix[2, 1]) - (keymatrix[2, 0] * keymatrix[0, 1])))) % 26;
                if (tempkeyInverse[1, 2] < 0)
                    tempkeyInverse[1, 2] += 26;

                tempkeyInverse[2, 2] = (multi_inverse * (((keymatrix[0, 0] * keymatrix[1, 1]) - (keymatrix[1, 0] * keymatrix[0, 1])))) % 26;
                if (tempkeyInverse[2, 2] < 0)
                    tempkeyInverse[2, 2] += 26;
                //getting the final keyInverse
                for (int col = 0; col < m; col++)
                {
                    for (int row = 0; row < m; row++)
                    {
                        if (row == col)
                        {
                            keyInverse[row, col] = tempkeyInverse[row, col];
                        }
                        else
                        {
                            keyInverse[row, col] = tempkeyInverse[col, row];
                        }
                    }
                }
                //solve the equation p=keyInverse*c  mod 26
                List<int> templist;
                List<int> outputTempList = new List<int>();
                int count2 = cipherText.Count;

                for (int i = 0; i <= count2; i++)
                {
                    templist = cipherText.GetRange(0, m);
                    //process the temp list and add it to cipher list
                    for (int j = 0; j < m; j++)
                    {
                        int num = 0;
                        for (int row = 0; row < m; row++)
                        {

                            int n = num;
                            num = (Convert.ToInt32(keyInverse[row, j]) * templist[row]);
                            num = n + num;
                        }
                        outputTempList.Add(num % 26);
                    }
                    templist.Clear();
                    cipherText.RemoveRange(0, m);

                    if (cipherText.Count == 0)
                    {
                        break;
                    }
                }
                return outputTempList;
            }
        }


        public List<int> Encrypt(List<int> plainText, List<int> key)
        {
            int m;
            List<int> Cipher = new List<int>();//output list
            m = Convert.ToInt32(Math.Sqrt(key.Count));

            int[,] keymatrix = new int[m, m];
            int count = 0;//to get the key list
            List<int> templist;
            List<int> outputTempList = new List<int>();
            //convert key list to matrix to deal with it easer 
            for (int col = 0; col < m; col++)
            {
                for (int row = 0; row < m; row++)
                {
                    keymatrix[row, col] = key[count];
                    count++;
                }
            }
            int count2 = plainText.Count;

            for (int i = 0; i <= count2; i++)  
            {
                templist = plainText.GetRange(0, m);
                //process the temp list and add it to cipher list
                for (int j = 0; j < m; j++)
                {
                    int num = 0;
                    for (int row = 0; row < m; row++)
                    {

                        int n = num;
                        num = (keymatrix[row, j] * templist[row]);
                        num = n + num;
                    }
                    outputTempList.Add(num % 26);
                }
                templist.Clear();
                plainText.RemoveRange(0, m);

                if (plainText.Count == 0)
                {
                    break;
                }
            }
            return outputTempList;
        }


        public List<int> Analyse3By3Key(List<int> plainText, List<int> cipherText)
        {
            int m;
            //List<int> Cipher = new List<int>();//output list
            m = Convert.ToInt32(Math.Sqrt(plainText.Count));

            int[,] plain_matrix = new int[m, m];
            double[,] tempplainInverse = new double[m, m];   //multi_inverse * sub matrices of key 
            double[,] plainInverse = new double[m, m];
            int[,] CipherTrans = new int[m, m];
            int[,] Cipher_matrix = new int[m, m];

            int count = 0;//to get the key list
            double multi_inverse = 0;//multiplicative inverse 
            //convert key list to matrix to deal with it easer 
            for (int col = 0; col < m; col++)
            {
                for (int row = 0; row < m; row++)
                {
                    plain_matrix[row, col] = plainText[count];
                    count++;
                }
            }

            int varcount = 0;
            for (int col = 0; col < m; col++)
            {
                for (int row = 0; row < m; row++)
                {
                    Cipher_matrix[row, col] = cipherText[varcount];
                    varcount++;
                }
            }

            for (int col = 0; col < m; col++)   //trans of cipher
            {
                for (int row = 0; row < m; row++)
                {

                    CipherTrans[row, col] = Cipher_matrix[col, row];

                }
            }

            List<int> cipherList = new List<int>();
            for (int col = 0; col < m; col++)  ///////////////////////
            {
                for (int row = 0; row < m; row++)
                {
                    cipherList.Add(CipherTrans[row, col]);
                }
            }

            //get det(k)
            int det = 0;
            det = (plain_matrix[0, 0] * (plain_matrix[1, 1] * plain_matrix[2, 2] - plain_matrix[1, 2] * plain_matrix[2, 1])) - (plain_matrix[1, 0] * (plain_matrix[0, 1] * plain_matrix[2, 2] - plain_matrix[0, 2] * plain_matrix[2, 1])) + plain_matrix[2, 0] * (plain_matrix[0, 1] * plain_matrix[1, 2] - plain_matrix[0, 2] * plain_matrix[1, 1]);
            det %= 26;
            if (det < 0)
                det += 26;
            //getting multi_inverse
            int[] q = new int[100];
            int[] A1 = new int[100];
            int[] A2 = new int[100];
            int[] A3 = new int[100];
            int[] B1 = new int[100];
            int[] B2 = new int[100];
            int[] B3 = new int[100];

            q[0] = 0;
            A1[0] = 1;
            A2[0] = 0;
            A3[0] = 26;
            B1[0] = 0;
            B2[0] = 1;
            B3[0] = det;
            int index = 1;
            while (index != 100)
            {
                q[index] = A3[index - 1] / B3[index - 1];
                A1[index] = B1[index - 1];
                A2[index] = B2[index - 1];

                A3[index] = B3[index - 1];
                B3[index] = A3[index - 1] - (B3[index - 1] * q[index]);
                B1[index] = A1[index - 1] - (q[index] * B1[index - 1]);
                B2[index] = A2[index - 1] - (q[index] * B2[index - 1]);

                if (B3[index] == 1)
                {
                    multi_inverse = (B2[index] % 26);
                    if (multi_inverse < 0)
                        multi_inverse += 26;
                    break;
                }
                if (B3[index] == 0)
                {
                    multi_inverse = B2[index];
                    break;
                }
                index++;
            }
            //multi_inverse * sub matrices of key 

            tempplainInverse[0, 0] = (multi_inverse * ((plain_matrix[1, 1] * plain_matrix[2, 2]) - (plain_matrix[2, 1] * plain_matrix[1, 2]))) % 26;
            if (tempplainInverse[0, 0] < 0)
                tempplainInverse[0, 0] += 26;

            tempplainInverse[1, 0] = (multi_inverse * (-((plain_matrix[0, 1] * plain_matrix[2, 2]) - (plain_matrix[2, 1] * plain_matrix[0, 2])))) % 26;
            if (tempplainInverse[1, 0] < 0)
                tempplainInverse[1, 0] += 26;

            tempplainInverse[2, 0] = (multi_inverse * (((plain_matrix[0, 1] * plain_matrix[1, 2]) - (plain_matrix[1, 1] * plain_matrix[0, 2])))) % 26;
            if (tempplainInverse[2, 0] < 0)
                tempplainInverse[2, 0] += 26;

            tempplainInverse[0, 1] = (multi_inverse * (-((plain_matrix[1, 0] * plain_matrix[2, 2]) - (plain_matrix[1, 2] * plain_matrix[2, 0])))) % 26;
            if (tempplainInverse[0, 1] < 0)
                tempplainInverse[0, 1] += 26;

            tempplainInverse[1, 1] = (multi_inverse * (((plain_matrix[0, 0] * plain_matrix[2, 2]) - (plain_matrix[0, 2] * plain_matrix[2, 0])))) % 26;
            if (tempplainInverse[1, 1] < 0)
                tempplainInverse[1, 1] += 26;

            tempplainInverse[2, 1] = (multi_inverse * (-((plain_matrix[0, 0] * plain_matrix[1, 2]) - (plain_matrix[0, 2] * plain_matrix[1, 0])))) % 26;
            if (tempplainInverse[2, 1] < 0)
                tempplainInverse[2, 1] += 26;

            tempplainInverse[0, 2] = (multi_inverse * (((plain_matrix[1, 0] * plain_matrix[2, 1]) - (plain_matrix[2, 0] * plain_matrix[1, 1])))) % 26;
            if (tempplainInverse[0, 2] < 0)
                tempplainInverse[0, 2] += 26;

            tempplainInverse[1, 2] = (multi_inverse * (-((plain_matrix[0, 0] * plain_matrix[2, 1]) - (plain_matrix[2, 0] * plain_matrix[0, 1])))) % 26;
            if (tempplainInverse[1, 2] < 0)
                tempplainInverse[1, 2] += 26;

            tempplainInverse[2, 2] = (multi_inverse * (((plain_matrix[0, 0] * plain_matrix[1, 1]) - (plain_matrix[1, 0] * plain_matrix[0, 1])))) % 26;
            if (tempplainInverse[2, 2] < 0)
                tempplainInverse[2, 2] += 26;
            //getting the final keyInverse
            for (int col = 0; col < m; col++)
            {
                for (int row = 0; row < m; row++)
                {
                    if (row == col)
                    {
                        plainInverse[row, col] = tempplainInverse[row, col];
                    }
                    else
                    {
                        plainInverse[row, col] = tempplainInverse[col, row];
                    }
                }
            }
            //solve the equation k=plainInverse*c  
            List<int> templist;
            List<int> outputTempList = new List<int>();
            int count2 = cipherList.Count;

            for (int i = 0; i <= count2; i++)
            {
                templist = cipherList.GetRange(0, m);
                //process the temp list and add it to cipher list
                for (int j = 0; j < m; j++)
                {
                    int num = 0;
                    for (int row = 0; row < m; row++)
                    {
                        int n = num;
                        num = (Convert.ToInt32(plainInverse[row, j]) * templist[row]);
                        num = n + num;
                    }
                    outputTempList.Add(num % 26);
                }
                templist.Clear();
                cipherList.RemoveRange(0, m);

                if (cipherList.Count == 0)
                {
                    break;
                }
            }
            return outputTempList;
        }

    }
}
