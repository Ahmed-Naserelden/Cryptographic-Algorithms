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
            //throw new NotImplementedException();
            string cipherText = "";

            foreach (char pChar in plainText)
            {
                char ru = pChar < 'a' ? 'A' : 'a';

                int pIndex = (int)(pChar - ru);

                int cIndex = (pIndex + key) % 26;

                char cChar = (char)(ru + cIndex);

                cipherText += cChar;
            }
            return cipherText;

        }
        public string Decrypt(string cipherText, int key)
        {
            string plainText = "";

            foreach (char cChar in cipherText)
            {
                char ru = cChar < 'a' ? 'A' : 'a';

                int cIndex = (int)(cChar - ru);

                int pIndex = (((cIndex - key) % 26) + 26) % 26;

                char pChar = (char)(ru + pIndex);

                plainText += pChar;
            }

            return plainText;
        }
        public int Analyse(string plainText, string cipherText)
        {
            int key = 0;

            int pChar = (int)(plainText[0] - 'a');

            int cChar = (int)(cipherText[0] - 'A');

            if (cChar >= pChar) key = (int)(cChar - pChar);

            else key = cChar + (26 - pChar);

            return key;
        }
    }
}