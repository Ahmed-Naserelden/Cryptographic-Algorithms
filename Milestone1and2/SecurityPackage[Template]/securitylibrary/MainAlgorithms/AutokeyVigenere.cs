﻿using System;
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
            throw new NotImplementedException();
        }

        public string Decrypt(string cipherText, string key)
        {
            throw new NotImplementedException();
        }

        public string Encrypt(string plainText, string key)
        {
            int index = 0;
            string cipherText = "";
            while(plainText.Length != key.Length)
            {
                key += plainText[index];
                index++;
            }

            int[,] letters = new int[26,26];
            for(int i = 0; i < 26; i++)
            {
                for(int j = 0; j < 26; j++)
                {
                    letters[i, j] = (int)'A' + (i + j) % 26;
                }
            }

            int Key_counter = 0;
            key = key.ToUpper();
            plainText = plainText.ToUpper();    
            for(int i = 0; i < plainText.Length;i++)
            {
                int row_no = Math.Abs((int)('A') - key[Key_counter]);
                int col_no = Math.Abs((int)('A') - plainText[i]);
                cipherText += (char)letters[row_no,col_no];
                Key_counter++;
            }
            

            return cipherText.ToUpper();
        }
    }
}
