using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace SecurityLibrary.RC4
{
    /// <summary>
    /// If the string starts with 0x.... then it's Hexadecimal not string
    /// </summary>
    public class RC4 : CryptographicTechnique
    {
        public override string Encrypt(string plainText, string key)
        {
            // throw new NotImplementedException();
            return CR4(plainText, key);

        }

        public override string Decrypt(string cipherText, string key)
        {
            // throw new NotImplementedException();
            return CR4(cipherText, key);
        }

        public static string cr4h(string content, string key)
        {
            string target = "";
            content = content.Substring(2);
            key = key.Substring(2);

            string[] Key = new string[key.Length / 2], 
                Content = new string[content.Length / 2];

            for (int p = 0; p < Content.Length; p++)
            {
                Content[p] = content[p * 2] + "" + content[p * 2 + 1];
            }

            for (int p = 0; p < Key.Length; p++)
            {
                Key[p] = key[p * 2] + "" + key[p * 2 + 1];
            }



            int[] S = new int[256];
            string[] T = new string[256];

            int i = 0, j = 0, t = 0, k = 0;

            // initial permutation  of S, T
            for (; i < 256; i++)
            {
                S[i] = i;
                T[i] = Key[i % Key.Length];
            }

            // initial permutation  of S
            i = 0; j = 0;

            for (; i < 256; i++)
            {
                j = (j + S[i] + Convert.ToInt32(T[i], 16)) % 256;

                // swap
                S[i] ^= S[j];
                S[j] ^= S[i];
                S[i] ^= S[j];
            }

            // stream generation
            i = 0; j = 0;


            while (target.Length != 2 * Content.Length)
            {
                i = (i + 1) % 256;
                j = (j + S[i]) % 256;

                // swap
                S[i] ^= S[j];
                S[j] ^= S[i];
                S[i] ^= S[j];

                t = (S[i] + S[j]) % 256;
                k = S[t];

                target += (
                    k ^ Convert.ToInt32(Content[i - 1], 16)
                ).ToString("X");
            }

            return "0x" + target;
        }
        
        public static string CR4(string content, string key)
        {

            if (key[0] == '0' && key[1] == 'x')
            {
                return cr4h(content, key);
            }

            string target = "";
            int[] S = new int[256];
            char[] T = new char[256];

            int i = 0, j = 0, t = 0, k = 0;

            // initial permutation  of S, T
            for (; i < 256; i++)
            {
                S[i] = i;
                T[i] = key[i % key.Length];
            }

            // initial permutation  of S
            i = 0; j = 0;
            for (; i < 256; i++)
            {
                j = (j + S[i] + T[i]) % 256;

                // swap
                S[i] ^= S[j];
                S[j] ^= S[i];
                S[i] ^= S[j];
            }

            // stream generation
            i = 0; j = 0;

            while (target.Length 
                != content.Length)
            {
                i = (i + 1) % 256;
                j = (j + S[i]) % 256;

                // swap
                S[i] ^= S[j];
                S[j] ^= S[i];
                S[i] ^= S[j];

                t = (S[i] + S[j]) % 256;
                k = S[t];

                target += (char)(content[i - 1] ^ k);

            }

            return target;
        }
        
    }
}
