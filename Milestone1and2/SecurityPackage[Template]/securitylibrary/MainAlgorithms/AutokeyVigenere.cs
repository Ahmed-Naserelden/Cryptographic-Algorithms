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
            string key = "";

            int[,] letters = new int[26, 26];
            for (int i = 0; i < 26; i++)
            {
                for (int j = 0; j < 26; j++)
                {
                    letters[i, j] = (int)'A' + (i + j) % 26;
                }
            }

            int cipher_counter = 0;
           // cipherText = cipherText;
            plainText = plainText.ToLower();
            for (int i = 0; i < plainText.Length; i++)
            {
                int plain_letter = Math.Abs((int)'a' - plainText[i]);
                for (int row = 0; row < 26; row++)
                {
                    if ((char)letters[row, plain_letter] == cipherText[cipher_counter])
                    {
                        key += (char)('a' + row);


                    }
                }
                cipher_counter++;
            }

            key = key.Replace(plainText, "");

            int key_len = key.Length;
            for (int i = 1; i < plainText.Length; i++)
            {
                string tmp = plainText.Remove(plainText.Length - i, i);
                Console.WriteLine(tmp);
                key = key.Replace(tmp, "");
                if (key.Length != key_len)
                {
                    break;
                }
            }
            return key;
        }

        public string Decrypt(string cipherText, string key)
        {
            string plainText = "";
            cipherText = cipherText.ToLower();
            key = key.ToLower();
            char tmp;
            for (int i = 0; i < cipherText.Length; i++)
            {
                int cipher_letter = Math.Abs((int)('a' - cipherText[i]));
                int key_letter = Math.Abs((int)('a' - key[i]));
                tmp = (char)(Math.Abs((cipher_letter - key_letter + 26)) % 26);
                tmp = (char)('a' + tmp);
                plainText += tmp;
                if (key.Length != cipherText.Length)
                    key += tmp;
            }
            return plainText;
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
