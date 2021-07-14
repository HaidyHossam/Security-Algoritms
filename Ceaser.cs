using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class Ceaser : ICryptographicTechnique<string, int>
    {
        public string Encrypt(string plainText, int key)
        {
            char[] char_in_table = new char[26];               //array of charecters 
            int[] char_index = new int[26];                    //array of charecters index
            int[] PT_index = new int[plainText.Length];                   //array of pt index
            int[] CT_index = new int[plainText.Length];                   //array of the resulted (index of p + key)mod 26
            char[] output_char = new char[plainText.Length];               //array of the resulted charecters
            char char_start = 'A';
            string out_of_encryption;
            if (key == 0)
            {
                out_of_encryption = plainText;


            }
            else
            {

                for (int i = 0; i < 26; i++)                       //loop for build the fixed index table 
                {
                    char_in_table[i] = char_start;
                    char_index[i] = i;
                    char_start++;

                }

                string string_plainText = plainText.ToUpper();
                char[] charecters = string_plainText.ToCharArray();      //split the input string into arr of char to deal with every char in the equation
                int index = 0;
                int pt_indexofindex = 0;
                int table_index = 0;
                int count = 1;
                for (int x = 0; x < (charecters.Length) * count; x++)
                {
                    if (charecters[index] == char_in_table[table_index])
                    {
                        PT_index[pt_indexofindex] = table_index;
                        if (pt_indexofindex == charecters.Length - 1)
                        {
                            break;
                        }

                        index++;
                        table_index = 0;
                        pt_indexofindex++;
                        count++;
                    }
                    else
                    {

                        table_index++;
                        count++;
                    }

                }
                for (int i = 0; i < charecters.Length; i++)
                {
                    CT_index[i] = (PT_index[i] + key) % 26;
                }

                int indexof_ctindex = 0;
                int indexof_charindex = 0;
                int outputindex = 0;
                for (int i = 0; i < charecters.Length * char_in_table.Length; i++)
                {
                    if (indexof_ctindex == charecters.Length)
                    {
                        break;
                    }
                    if (CT_index[indexof_ctindex] == char_index[indexof_charindex])
                    {
                        output_char[outputindex] = char_in_table[char_index[indexof_charindex]];

                        indexof_ctindex++;
                        indexof_charindex = 0;
                        outputindex++;
                    }
                    else
                    {
                        indexof_charindex++;
                    }
                }

                out_of_encryption = new string(output_char);

            }

            return out_of_encryption;
        }

        public string Decrypt(string cipherText, int key)
        {
            char[] char_in_table = new char[26];               //array of charecters 
            int[] char_index = new int[26];                    //array of charecters index
            int[] PT_index = new int[cipherText.Length];                   //array of pt index
            int[] CT_index = new int[cipherText.Length];                   //array of the resulted (index of p + key)mod 26
            char[] output_char = new char[cipherText.Length];               //array of the resulted charecters
            char char_start = 'A';
            string out_of_decryption;

            for (int i = 0; i < 26; i++)                       //loop for build the fixed index table 
            {
                char_in_table[i] = char_start;
                char_index[i] = i;
                char_start++;

            }

            string string_cipherText = cipherText.ToUpper();
            char[] charecters = string_cipherText.ToCharArray();      //split the input string into arr of char to deal with every char in the equation
            int index = 0;
            int CT_indexofindex = 0;
            int table_index = 0;
            int count = 1;
            for (int x = 0; x < (charecters.Length) * count; x++)
            {
                if (charecters[index] == char_in_table[table_index])
                {
                    CT_index[CT_indexofindex] = table_index;
                    if (CT_indexofindex == charecters.Length - 1)
                    {
                        break;
                    }

                    index++;
                    table_index = 0;
                    CT_indexofindex++;
                    count++;
                }
                else
                {

                    table_index++;
                    count++;
                }

            }


            for (int i = 0; i < charecters.Length; i++)
            {
                int Result;
                Result = CT_index[i] - key;
                if (Result < 0)
                {
                    Result += 26;
                    PT_index[i] = Result;
                }
                else
                {
                    PT_index[i] = Result;
                }
            }

            int indexof_ptindex = 0;
            int indexof_charindex = 0;
            int outputindex = 0;
            for (int i = 0; i < charecters.Length * char_in_table.Length; i++)
            {
                if (indexof_ptindex == charecters.Length)
                {
                    break;
                }
                if (PT_index[indexof_ptindex] == char_index[indexof_charindex])
                {
                    output_char[outputindex] = char_in_table[char_index[indexof_charindex]];

                    indexof_ptindex++;
                    indexof_charindex = 0;
                    outputindex++;
                }
                else
                {
                    indexof_charindex++;
                }
            }

            out_of_decryption = new string(output_char);
            return out_of_decryption;
        }

        public int Analyse(string plainText, string cipherText)
        {
            string PlainText = plainText.ToLower();
            string CipherText = cipherText.ToLower();
            char[] Alphabetic = new char[26];
            char Char_Start = 'a';
            int Key = 0;
            int Diff = 0;
            int PlainIndex = 0;
            int CipherIndex = 0;

            for (int i = 0; i < 26; i++)
            {
                Alphabetic[i] = Char_Start;
                Char_Start++;
            }

            for (int i = 0; i < Alphabetic.Count(); i++)
            {
                if (PlainText[0] == Alphabetic[i])
                {
                    PlainIndex = i;
                    break;
                }
            }

            for (int i = 0; i < Alphabetic.Count(); i++)
            {
                if (CipherText[0] == Alphabetic[i])
                {
                    CipherIndex = i;
                    break;
                }
            }

            Diff = CipherIndex - PlainIndex;

            if (Diff < 0)
            {
                Key = 26 - Math.Abs(Diff);
            }
            else
            {
                Key = Diff;
            }

            return Key;
        }
    }
}
