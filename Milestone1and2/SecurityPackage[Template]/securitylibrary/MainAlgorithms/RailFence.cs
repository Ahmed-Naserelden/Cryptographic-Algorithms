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
            //throw new NotImplementedException();
            plainText = plainText.ToLower();
            cipherText = cipherText.ToLower();
            int key = 1;
            for(int i=0; i < 100; i++)
            {
                string myCipher = Encrypt(plainText, key);
                if(String.Compare(myCipher,cipherText) == 0)
                {
                    break;
                }
                key++;
            }
            return key;
        }

        public string Decrypt(string cipherText, int key)
        {
            //throw new NotImplementedException();

            decimal x = key;
            decimal y = Math.Ceiling(cipherText.Length / x);
            char[,] board = new char[(int)x, (int)y];
            int index = 0;
            for (int i = 0; i < x; i++)
            {
                for (int j = 0; j < y; j++)
                {
                    if (index != cipherText.Length)
                    {
                        board[i, j] = cipherText[index];
                        index++;
                    }
                }
            }

            string plainText = "";
            for (int j = 0; j < y; j++)
            {
                for (int i = 0; i < x; i++)
                {
                    plainText += board[i, j];
                }
            }
            return plainText;

        }

        public string Encrypt(string plainText, int key)
        {
            //throw new NotImplementedException();

            //preparing the dimentions of the matrix
            decimal x = key;
            decimal y = Math.Ceiling(plainText.Length / x);

            //initialize the matrix
            char[,] board = new char[(int)x, (int)y];

            int index = 0;
            for (int i = 0; i < y; i++)
            {
                for (int j = 0; j < x; j++)
                {
                    if (index != plainText.Length)
                    {
                        board[j, i] = plainText[index];
                        index++;
                    }
                }
            }
            string cipherText = "";
            for (int j = 0; j < x; j++)
            {
                for (int i = 0; i < y; i++)
                {
                    cipherText = cipherText + board[j, i];
                }
            }
            return cipherText;
        }
    }
}
