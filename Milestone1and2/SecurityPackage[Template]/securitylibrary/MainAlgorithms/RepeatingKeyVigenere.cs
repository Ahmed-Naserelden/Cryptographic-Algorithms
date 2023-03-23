using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class RepeatingkeyVigenere : ICryptographicTechnique<string, string>
    {
        public string Analyse(string plainText, string cipherText)
        {
            string pi = "";
            for (int i = 0; i < cipherText.Length; i++)
            {

                char l = plainText[i] < 'a' ? 'A' : 'a';
                int j = (int)(plainText[i] - l);
                char k = cipherText[i] < 'a' ? 'A' : 'a';
                int a = (int)(cipherText[i] - k);
                int sum = (a - j);
                if (sum < 0)
                    sum += 26;
                pi += (char)(sum + 'a');
            }
            string key = "";
            key += pi.Substring(0, 3);
            string spare = pi.Substring(3);
            if (spare.Contains(key) == true)
            {
                int i = spare.IndexOf(key);
                spare = spare.Remove(i);
                key += spare;
                return key;
            }
            else
                return pi;
        }

        public string Decrypt(string cipherText, string key)
        {
            int cipherTextlength = cipherText.Length;
            int keylength = key.Length;
            string keystream = key;
            if (cipherTextlength > keylength)
            {
                for (int i = 0; i < cipherTextlength; i++)
                {

                    keystream += key;

                    if (keystream.Length == cipherTextlength)
                    {
                        break;
                    }

                }
            }
            if (keystream.Length > cipherTextlength)
            {
                int diffkey = keystream.Length - cipherTextlength;
                keystream = keystream.Remove(cipherTextlength);

            }
            string pi = "";
            cipherText = cipherText.ToLower();
            keystream = keystream.ToLower();
            for (int i = 0; i < cipherTextlength; i++)
            {
                int j = Convert.ToInt32(cipherText[i]);
                int a = Convert.ToInt32(keystream[i]);
                int sum = (j - a);
                if (sum < 0)
                {
                    sum += 26;
                }
                pi += (char)(sum + 'a');
            }
            return pi;
        }

        public string Encrypt(string plainText, string key)
        {


            int plaintextlength = plainText.Length;
            int keylength = key.Length;
            string keystream = key;
            if (plaintextlength > keylength)
            {

                for (int i = 0; i < plaintextlength; i++)
                {

                    keystream += key;

                    if (keystream.Length == plaintextlength)
                    {
                        break;
                    }

                }


            }
            if (keystream.Length > plaintextlength)
            {
                int diffkey = keystream.Length - plaintextlength;
                keystream = keystream.Remove(plaintextlength);

            }



            string ct = "";
            for (int i = 0; i < plaintextlength; i++)
            {

                char l = plainText[i] < 'a' ? 'A' : 'a';
                int j = (int)(plainText[i] - l);
                char k = keystream[i] < 'a' ? 'A' : 'a';
                int a = (int)(keystream[i] - k);
                int sum = (j + a) % 26;
                ct += (char)(sum + 'a');
            }
            return ct;



        }
    }
}