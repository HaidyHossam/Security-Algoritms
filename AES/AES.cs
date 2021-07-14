using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.AES
{
    /// <summary>
    /// If the string starts with 0x.... then it's Hexadecimal not string
    /// </summary>
    public class AES : CryptographicTechnique
    {
        public static string[,] sBox = new string[16, 16]
        {   {"63", "7c", "77", "7b", "f2", "6b", "6f", "c5", "30", "01", "67", "2b","fe","d7", "ab", "76"},
            {"ca", "82", "c9", "7d" ,"fa", "59", "47", "f0", "ad", "d4", "a2", "af","9c","a4", "72", "c0"},
            {"b7", "fd", "93", "26", "36", "3f", "f7", "cc", "34", "a5", "e5", "f1","71","d8", "31", "15"},
            {"04", "c7", "23", "c3", "18", "96", "05", "9a", "07", "12", "80", "e2","eb","27", "b2", "75"},
            {"09", "83", "2c", "1a", "1b", "6e", "5a", "a0", "52", "3b", "d6", "b3","29","e3", "2f", "84"},
            {"53", "d1", "00", "ed", "20", "fc", "b1", "5b", "6a", "cb", "be", "39","4a","4c", "58", "cf"},
            {"d0", "ef", "aa", "fb", "43", "4d", "33", "85", "45", "f9", "02", "7f","50","3c", "9f", "a8"},
            {"51", "a3", "40", "8f", "92", "9d", "38", "f5", "bc", "b6", "da", "21","10","ff", "f3", "d2"},
            {"cd", "0c", "13", "ec", "5f", "97", "44", "17", "c4", "a7", "7e", "3d","64","5d", "19", "73"},
            {"60", "81", "4f", "dc", "22", "2a", "90", "88", "46", "ee", "b8", "14","de","5e", "0b", "db"},
            {"e0", "32", "3a", "0a", "49", "06", "24", "5c", "c2", "d3", "ac", "62","91","95", "e4", "79"},
            {"e7", "c8", "37", "6d", "8d", "d5", "4e", "a9", "6c", "56", "f4", "ea","65","7a", "ae", "08"},
            {"ba", "78", "25", "2e", "1c", "a6", "b4", "c6", "e8", "dd", "74", "1f","4b","bd", "8b", "8a"},
            {"70", "3e", "b5", "66", "48", "03", "f6", "0e", "61", "35", "57", "b9","86","c1", "1d", "9e"},
            {"e1", "f8", "98", "11", "69", "d9", "8e", "94", "9b", "1e", "87", "e9","ce","55", "28", "df"},
            {"8c", "a1", "89", "0d", "bf", "e6", "42", "68", "41", "99", "2d", "0f","b0","54", "bb", "16"}
        };

        public static string[,] inverseSBox = new string[16, 16]

        {
            {"52", "09", "6a","d5", "30", "36", "a5", "38", "bf", "40", "a3", "9e", "81", "f3", "d7", "fb"},
            {"7c", "e3", "39", "82" ,"9b", "2f", "ff", "87", "34", "8e", "43", "44", "c4", "de", "e9", "cb"},
            {"54", "7b", "94", "32", "a6", "c2", "23", "3d", "ee", "4c",  "95", "0b", "42", "fa", "c3", "4e"},
            {"08", "2e", "a1", "66", "28", "d9", "24", "b2", "76", "5b", "a2", "49", "6d", "8b", "d1", "25"},
            {"72", "f8", "f6", "64", "86", "68", "98", "16", "d4", "a4", "5c", "cc", "5d", "65", "b6", "92"},
            {"6c", "70", "48", "50", "fd", "ed", "b9", "da", "5e", "15", "46", "57", "a7", "8d", "9d", "84"},
            {"90", "d8", "ab", "00", "8c", "bc", "d3", "0a", "f7", "e4", "58", "05", "b8", "b3", "45", "06"},
            {"d0", "2c", "1e", "8f", "ca", "3f", "0f", "02", "c1", "af", "bd", "03", "01", "13", "8a", "6b"},
            {"3a", "91", "11", "41", "4f", "67", "dc", "ea", "97", "f2", "cf", "ce", "f0", "b4", "e6", "73"},
            {"96", "ac", "74", "22", "e7", "ad", "35", "85", "e2", "f9", "37", "e8", "1c", "75", "df", "6e"},
            {"47", "f1", "1a", "71", "1d", "29", "c5", "89", "6f", "b7", "62", "0e", "aa", "18", "be", "1b"},
            {"fc", "56", "3e", "4b", "c6", "d2", "79", "20", "9a", "db", "c0", "fe", "78", "cd", "5a", "f4"},
            {"1f", "dd", "a8", "33", "88", "07", "c7", "31", "b1", "12", "10", "59", "27", "80", "ec", "5f"},
            {"60", "51", "7f", "a9", "19", "b5", "4a", "0d", "2d", "e5", "7a", "9f", "93", "c9", "9c", "ef"},
            {"a0", "e0", "3b", "4d", "ae", "2a", "f5", "b0", "c8", "eb", "bb", "3c", "83", "53", "99", "61"},
            {"17", "2b", "04", "7e", "ba", "77", "d6", "26", "e1", "69", "14", "63", "55", "21", "0c", "7d"}

        };
        public static string[,] Rcon = new string[4, 10]
        {           
            {"01","02","04","08","10","20","40","80","1b","36"},
            {"00","00","00","00","00","00","00","00","00","00"},
            {"00","00","00","00","00","00","00","00","00","00"},
            {"00","00","00","00","00","00","00","00","00","00"}
        };

        public static string[,] MixColumnMatrix = new string[4, 4]
        {
            {"02","03","01","01"},
            {"01","02","03","01"},
            {"01","01","02","03"},
            {"03","01","01","02"}
        };
        public static string[,] InvMixColumnMatrix = new string[4, 4]
        {
            {"0e","0b","0d","09"},
            {"09","0e","0b","0d"},
            {"0d","09","0e","0b"},
            {"0b","0d","09","0e"}
        };
        public static string[,] stringToMatrix(string state)
        {
            string[,] stateArr = new string[4, 4];
            int ind = 2;
            while (ind != state.Length)
            {
                for (int i = 0; i < 4; i++) //state from string to array
                {
                    for (int j = 0; j < 4; j++)
                    {
                        stateArr[j, i] = state.Substring(ind, 2);
                        ind += 2;
                    }
                }
            }
            return stateArr;
        }
        public static string[,] subBytes(string[,] stateArr,string[,] BOX)
        {
            string[,] newState = new string[4, 4];
            int row = 0;
            int col = 0;
            for (int i = 0; i < 4; i++) //sub bytes
            {
                for (int j = 0; j < 4; j++)
                {
                    if (stateArr[i, j].Substring(0, 1).Equals("a") || stateArr[i, j].Substring(0, 1).Equals("A"))
                    {
                        row = 10;
                    }
                    else if (stateArr[i, j].Substring(0, 1).Equals("b") || stateArr[i, j].Substring(0, 1).Equals("B"))
                    {
                        row = 11;
                    }
                    else if (stateArr[i, j].Substring(0, 1).Equals("c") || stateArr[i, j].Substring(0, 1).Equals("C"))
                    {
                        row = 12;
                    }
                    else if (stateArr[i, j].Substring(0, 1).Equals("d") || stateArr[i, j].Substring(0, 1).Equals("D"))
                    {
                        row = 13;
                    }
                    else if (stateArr[i, j].Substring(0, 1).Equals("e") || stateArr[i, j].Substring(0, 1).Equals("E"))
                    {
                        row = 14;
                    }
                    else if (stateArr[i, j].Substring(0, 1).Equals("f") || stateArr[i, j].Substring(0, 1).Equals("F"))
                    {
                        row = 15;
                    }
                    else
                    {
                        row = int.Parse(stateArr[i, j].Substring(0, 1));
                    }

                    if (stateArr[i, j].Substring(1, 1).Equals("a") || stateArr[i, j].Substring(1, 1).Equals("A"))
                    {
                        col = 10;
                    }
                    else if (stateArr[i, j].Substring(1, 1).Equals("b") || stateArr[i, j].Substring(1, 1).Equals("B"))
                    {
                        col = 11;
                    }
                    else if (stateArr[i, j].Substring(1, 1).Equals("c") || stateArr[i, j].Substring(1, 1).Equals("C"))
                    {
                        col = 12;
                    }
                    else if (stateArr[i, j].Substring(1, 1).Equals("d") || stateArr[i, j].Substring(1, 1).Equals("D"))
                    {
                        col = 13;
                    }
                    else if (stateArr[i, j].Substring(1, 1).Equals("e") || stateArr[i, j].Substring(1, 1).Equals("E"))
                    {
                        col = 14;
                    }
                    else if (stateArr[i, j].Substring(1, 1).Equals("f") || stateArr[i, j].Substring(1, 1).Equals("F"))
                    {
                        col = 15;
                    }
                    else
                    {
                        col = int.Parse(stateArr[i, j].Substring(1, 1));
                    }

                    newState[i, j] = BOX[row, col];
                }
            }
            return newState;
        }
        public static string[,] KeysubBytes(string[,] KeyArr, string[,] BOX)
        {
            string[,] newKey = KeyArr;
            int row = 0;
            int col = 0;
            for (int i = 0; i < 4; i++) //sub bytes
            {
                if (KeyArr[i, 3].Substring(0, 1).Equals("a") || KeyArr[i, 3].Substring(0, 1).Equals("A"))
                {
                    row = 10;
                }
                else if (KeyArr[i, 3].Substring(0, 1).Equals("b") || KeyArr[i, 3].Substring(0, 1).Equals("B"))
                {
                    row = 11;
                }
                else if (KeyArr[i, 3].Substring(0, 1).Equals("c") || KeyArr[i, 3].Substring(0, 1).Equals("C"))
                {
                    row = 12;
                }
                else if (KeyArr[i, 3].Substring(0, 1).Equals("d") || KeyArr[i, 3].Substring(0, 1).Equals("D"))
                {
                    row = 13;
                }
                else if (KeyArr[i, 3].Substring(0, 1).Equals("e") || KeyArr[i, 3].Substring(0, 1).Equals("E"))
                {
                    row = 14;
                }
                else if (KeyArr[i, 3].Substring(0, 1).Equals("f") || KeyArr[i, 3].Substring(0, 1).Equals("F"))
                {
                    row = 15;
                }
                else
                {
                    row = int.Parse(KeyArr[i, 3].Substring(0, 1));
                }

                if (KeyArr[i, 3].Substring(1, 1).Equals("a") || KeyArr[i, 3].Substring(1, 1).Equals("A"))
                {
                    col = 10;
                }
                else if (KeyArr[i, 3].Substring(1, 1).Equals("b") || KeyArr[i, 3].Substring(1, 1).Equals("B"))
                {
                    col = 11;
                }
                else if (KeyArr[i, 3].Substring(1, 1).Equals("c") || KeyArr[i, 3].Substring(1, 1).Equals("C"))
                {
                    col = 12;
                }
                else if (KeyArr[i, 3].Substring(1, 1).Equals("d") || KeyArr[i, 3].Substring(1, 1).Equals("D"))
                {
                    col = 13;
                }
                else if (KeyArr[i, 3].Substring(1, 1).Equals("e") || KeyArr[i, 3].Substring(1, 1).Equals("E"))
                {
                    col = 14;
                }
                else if (KeyArr[i, 3].Substring(1, 1).Equals("f") || KeyArr[i, 3].Substring(1, 1).Equals("F"))
                {
                    col = 15;
                }
                else
                {
                    col = int.Parse(KeyArr[i, 3].Substring(1, 1));
                }

                newKey[i, 3] = BOX[row, col];
            }

            return newKey;
        }
        public static string[,] shiftRows(string[,] state)
        {
            string temp = "";
            string temp2 = "";
            string temp3 = "";

            //rotate over 1 byte
            temp = state[1, 0];
            state[1, 0] = state[1, 1];
            state[1, 1] = state[1, 2];
            state[1, 2] = state[1, 3];
            state[1, 3] = temp;

            //rotate over 2 bytes
            temp = state[2, 2];
            temp2 = state[2, 3];
            state[2, 2] = state[2, 0];
            state[2, 3] = state[2, 1];
            state[2, 1] = temp2;
            state[2, 0] = temp;

            //rotate over 3 bytes
            temp = state[3, 0];
            temp2 = state[3, 1];
            temp3 = state[3, 2];
            state[3, 0] = state[3, 3];
            state[3, 1] = temp;
            state[3, 2] = temp2;
            state[3, 3] = temp3;

            return state;
        }
        public static string[,] InV_shiftRows(string[,] state)
        {
            string temp = "";
            string temp2 = "";
            string temp3 = "";

            //rotate over 1 byte
            temp = state[1, 3];
            state[1, 3] = state[1, 2];
            state[1, 2] = state[1, 1];
            state[1, 1] = state[1, 0];
            state[1, 0] = temp;

            //rotate over 2 bytes
            temp = state[2, 2];
            temp2 = state[2, 3];

            state[2, 3] = state[2, 1];
            state[2, 2] = state[2, 0];
            state[2, 1] = temp2;
            state[2, 0] = temp;

            //rotate over 3 bytes
            temp = state[3, 0];
            temp2 = state[3, 1];
            temp3 = state[3, 3];
            string temp4 = state[3, 2];
            state[3, 0] = temp2;

            state[3, 1] = temp4;
            state[3, 2] = temp3;
            state[3, 3] = temp;

            return state;
        }
        public static string B_1 = "1B";
        public static long MulBy2(long Num)
        {
            long Result = Num * 2;
            if (Result.ToString("X").Length == 3)
            {
                Result = Convert.ToInt64(Result.ToString("X").Substring(1, 2), 16);
                Result = Result ^ Convert.ToInt64(B_1, 16);
            }
            return Result;
        }
        public static long MulByE(long Num)
        {
            long Result = MulBy2(MulBy2(MulBy2(Num))) ^ MulBy2(MulBy2(Num)) ^ MulBy2(Num);
            if (Result.ToString("X").Length == 3)
                Result = Result ^ Convert.ToInt64(B_1, 16);
            return Result;
        }
        public static long MulBy9(long Num)
        {
            long Result = MulBy2(MulBy2(MulBy2(Num))) ^ Num;
            if (Result.ToString("X").Length == 3)
                Result = Result ^ Convert.ToInt64(B_1, 16);
            return Result;
        }
        public static long MulByD(long Num)
        {
            long Result = MulBy2(MulBy2(MulBy2(Num))) ^ MulBy2(MulBy2(Num)) ^ Num;
            if (Result.ToString("X").Length == 3)
                Result = Result ^ Convert.ToInt64(B_1, 16);
            return Result;
        }
        public static long MulByB(long Num)
        {
            long Result = MulBy2(MulBy2(MulBy2(Num))) ^ MulBy2(Num) ^ Num;
            if (Result.ToString("X").Length == 3)
                Result = Result ^ Convert.ToInt64(B_1, 16);
            return Result;
        }
        public static string[,] InvMixColumn(string[,] State)
        {
            string[,] Result = new string[4, 4];
            int ResultCountR = 0, ResultCountC = 0;

            for (int i = 0; i < 4; i++)
            {
                string Num1Str = State[0, i];
                string Num2Str = State[1, i];
                string Num3Str = State[2, i];
                string Num4Str = State[3, i];
                long Num1 = Convert.ToInt64(Num1Str, 16);
                long Num2 = Convert.ToInt64(Num2Str, 16);
                long Num3 = Convert.ToInt64(Num3Str, 16);
                long Num4 = Convert.ToInt64(Num4Str, 16);
                long b = Convert.ToInt64("0b", 16);
                long d = Convert.ToInt64("0d", 16);
                long e = Convert.ToInt64("0e", 16);

                for (int j = 0; j < 4; j++)
                {
                    long[] ResultArr = new long[4];

                    for (int k = 0; k < 4; k++)
                    {
                        string MatrixValStr = InvMixColumnMatrix[j, k];
                        long MatrixVal = Convert.ToInt64(MatrixValStr, 16);

                        string NumStr = State[k, i];
                        long Num = Convert.ToInt64(NumStr, 16);

                        if (MatrixVal == e)
                            ResultArr[k] = MulByE(Num);
                        else if (MatrixVal == b)
                            ResultArr[k] = MulByB(Num);
                        else if (MatrixVal == 9)
                            ResultArr[k] = MulBy9(Num);
                        else if (MatrixVal == d)
                            ResultArr[k] = MulByD(Num);
                    }

                    long Value = ResultArr[0] ^ ResultArr[1] ^ ResultArr[2] ^ ResultArr[3];

                    string HexValue = Value.ToString("X");

                    if (HexValue.Length == 3)
                        Result[ResultCountR, ResultCountC] = HexValue.Substring(1, 2);
                    else if (HexValue.Length == 1)
                        Result[ResultCountR, ResultCountC] = "0" + HexValue;
                    else
                        Result[ResultCountR, ResultCountC] = HexValue;
                    ResultCountR++;
                }
                ResultCountC++;
                ResultCountR = 0;
            }
            return Result;
        }
        public static string[,] MixColumn(string[,] State)
        {
            string[,] Result = new string[4, 4];
            int ResultCountR = 0, ResultCountC = 0;
            string B_1 = "1B";
            for (int i = 0; i < 4; i++)
            {
                string Num1Str = State[0, i];
                string Num2Str = State[1, i];
                string Num3Str = State[2, i];
                string Num4Str = State[3, i];
                long Num1 = Convert.ToInt64(Num1Str, 16);
                long Num2 = Convert.ToInt64(Num2Str, 16);
                long Num3 = Convert.ToInt64(Num3Str, 16);
                long Num4 = Convert.ToInt64(Num4Str, 16);
                for (int j = 0; j < 4; j++)
                {
                    long[] ResultArr = new long[4];

                    for (int k = 0; k < 4; k++)
                    {
                        string MatrixValStr = MixColumnMatrix[j, k];
                        long MatrixVal = Convert.ToInt64(MatrixValStr, 16);

                        string NumStr = State[k, i];
                        long Num = Convert.ToInt64(NumStr, 16);

                        if (MatrixVal == 2)
                        {
                            ResultArr[k] = Num * MatrixVal;
                            if (ResultArr[k].ToString("X").Length == 3)
                                ResultArr[k] = ResultArr[k] ^ Convert.ToInt64(B_1, 16);
                        }
                        else if (MatrixVal == 3)
                        {
                            ResultArr[k] = Num * 2;
                            if (ResultArr[k].ToString("X").Length == 3)
                            {
                                ResultArr[k] = ResultArr[k] ^ Num;
                                ResultArr[k] = ResultArr[k] ^ Convert.ToInt64(B_1, 16);
                            }
                            else
                                ResultArr[k] = ResultArr[k] ^ Num;
                        }
                        else
                            ResultArr[k] = Num * MatrixVal;
                    }

                    long Value = ResultArr[0] ^ ResultArr[1] ^ ResultArr[2] ^ ResultArr[3];
                    string HexValue = Value.ToString("X");
                    if (HexValue.Length == 3)
                        Result[ResultCountR, ResultCountC] = HexValue.Substring(1, 2);
                    else if (HexValue.Length == 1)
                        Result[ResultCountR, ResultCountC] = "0" + HexValue;
                    else
                        Result[ResultCountR, ResultCountC] = HexValue;
                    ResultCountR++;
                }
                ResultCountC++;
                ResultCountR = 0;
            }
            return Result;
        }

        public static string XOR(string first, string second)
        {
            long Num1 = Convert.ToInt64(first, 16);
            long Num2 = Convert.ToInt64(second, 16);
            long result = Num1 ^ Num2;
            string hexResult = result.ToString("x");
            return hexResult;
        }
        

        public static string MatrixToString(string[,] matrix)
        {
            string Matrixstr = "0x";
            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    Matrixstr += matrix[j, i];
                }
            }
            return Matrixstr;
        }

        public static string[,] GenerateRoundKey(int round, string mainKey,string[,] BOX)
        {
            string[,] Key = new string[4, 4];
            string[,] MKey = new string[4, 4];
            int ind = 2;
            while (ind != mainKey.Length)
            {
                for (int i = 0; i < 4; i++) //Key from string to array
                {
                    for (int j = 0; j < 4; j++)
                    {
                        Key[j, i] = mainKey.Substring(ind, 2);
                        MKey[j, i] = mainKey.Substring(ind, 2);
                        ind += 2;
                    }
                }
            }
            //step1 rotate
            string temp = Key[0, 3];
            Key[0, 3] = Key[1, 3];
            Key[1, 3] = Key[2, 3];
            Key[2, 3] = Key[3, 3];
            Key[3, 3] = temp;

            //step2 sub
            string[,] KeyV2 = new string[4, 4];
            KeyV2 = KeysubBytes(Key,BOX);

            //step3
            string[,] NewRoundKey = new string[4, 4];
            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    if (j == 0)
                    {
                        string a = XOR(MKey[i, j], KeyV2[i, 3]);
                        if (a.Length == 1)
                        {
                            a = "0" + a;
                        }
                        string b = XOR(a, Rcon[i, round]);
                        if (b.Length == 1)
                        {
                            b = "0" + b;
                        }
                        NewRoundKey[i, j] = b;
                    }
                    else
                    {
                        string x = MKey[i, j];
                        string y = NewRoundKey[i, j - 1];
                        string a = XOR(x, y);
                        if (a.Length == 1)
                        {
                            a = "0" + a;
                        }
                        NewRoundKey[i, j] = a;
                    }
                }
            }
            return NewRoundKey;
        }
        public static string[,] addRoundKey(string[,] state, string[,] roundKey)
        {
            string[,] newState = new string[4, 4];

            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    int value1 = Convert.ToInt32(state[j, i], 16);
                    int value2 = Convert.ToInt32(roundKey[j, i], 16);
                    string res = "";
                    res = XOR(state[j, i], roundKey[j, i]);
                    if (res.Length == 1)
                    {
                        res = "0" + res;
                    }
                    newState[j, i] = res;
                }
            }
            return newState;
        }
        public static string[] keys = new string[11];
        public override string Decrypt(string cipherText, string key)
        {
            string[,] state = stringToMatrix(cipherText);
            keys[0] = key;

            string[,] roundKey = new string[4, 4];
            for (int i = 0; i < 9; i++)
            {
                roundKey = GenerateRoundKey(i, key, sBox);
                key = MatrixToString(roundKey);
                keys[i + 1] = key;
            }
            string[,] rKey = GenerateRoundKey(9, key, sBox);
            string rrkey = MatrixToString(rKey);
            keys[10] = rrkey;
            string[,] newState = addRoundKey(state, rKey);
            string[,] shiftState = new string[4, 4];
            string[,] subState = new string[4, 4];

            int ind = 9;
            for (int i = 0; i < 9; i++)
            {
                shiftState = InV_shiftRows(newState);
                subState = subBytes(shiftState, inverseSBox);
                roundKey = stringToMatrix(keys[ind]);
                ind--;
                rrkey = MatrixToString(roundKey);
                newState = addRoundKey(subState, roundKey);
                newState = InvMixColumn(newState);
            }

            string[,] roundStateFinal = new string[4, 4];
            string[,] shiftStateFinal = new string[4, 4];
            string[,] subStateFinal = new string[4, 4];

            shiftStateFinal = InV_shiftRows(newState);
            subStateFinal = subBytes(shiftStateFinal, inverseSBox);

            roundKey = stringToMatrix(keys[0]);
            roundStateFinal = addRoundKey(subStateFinal, roundKey);

            string plain = MatrixToString(roundStateFinal);
            return plain;
        }

        public override string Encrypt(string plainText, string key)
        {
            string[,] state = stringToMatrix(plainText);
            string[,] rKey = stringToMatrix(key);
            string[,] newState = addRoundKey(state, rKey);
            string[,] shiftState = new string[4, 4];
            string[,] subState = new string[4, 4];
            string[,] mixState = new string[4, 4];
            string[,] roundKey = new string[4, 4];
            for (int i = 0; i < 9; i++)
            {
                subState = subBytes(newState,sBox);
                shiftState = shiftRows(subState);
                mixState = MixColumn(shiftState);
                roundKey = GenerateRoundKey(i, key,sBox);
                key = MatrixToString(roundKey);
                newState = addRoundKey(mixState, roundKey);
            }

            string[,] roundStateFinal = new string[4, 4];
            string[,] shiftStateFinal = new string[4, 4];
            string[,] subStateFinal = new string[4, 4];

            subStateFinal = subBytes(newState,sBox);
            shiftStateFinal = shiftRows(subStateFinal);
            roundKey = GenerateRoundKey(9, key,sBox);
            roundStateFinal = addRoundKey(shiftStateFinal, roundKey);

            string cipher = MatrixToString(roundStateFinal);
            return cipher;
        }
    }
}
