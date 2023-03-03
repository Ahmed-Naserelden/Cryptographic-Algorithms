using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class Monoalphabetic : ICryptographicTechnique<string, string>
    {
        struct pair
        {
            public int x;
            public int y;
        }

        public string Analyse(string plainText, string cipherText)
        {
            // throw new NotImplementedException();
            string key = "";
            char[] chars = new char[26];
            bool[] vistied = new bool[26];
            for (int i = 0; i < chars.Length; i++) chars[i] = '*';

            for (int i = 0; i < plainText.Length; i++){
                chars[plainText[i] - 'a'] = Char.ToLower(cipherText[i]);
                vistied[cipherText[i]-'A'] = true;
            }
            
            for (int i = 0; i < 26; i++)
            {
                if (chars[i] != '*')
                    key += chars[i];
                else
                {
                    int indx = 0;
                    while (indx < 26 && vistied[indx] == true) indx++;
                    vistied[indx] = true;
                    key += (char)('a' + indx);
                }
            }
            /*
            for(int i = 0; i < 26; i++)
            {
                if (chars[i]=='*')
                    key += (char)('a' + i);
            }*/
            return key;
        }
        public string Decrypt(string cipherText, string key)
        {
            string plainText = "";
            foreach (char ch in cipherText)
            {
                int idx = key.IndexOf(Char.ToLower(ch));
                plainText += (char)('a' + idx);
            }
            return plainText;
        }
        public string Encrypt(string plainText, string key)
        {
            string cipherText = "";
            char ru;

            foreach (char ch in plainText)
            {
                ru = ch < 'a' ? 'A' : 'a';
                cipherText += key[ch - ru];
            }

            return cipherText;
        }
        /// <summary>
        /// Frequency Information:
        /// E   12.51%
        /// T	9.25
        /// A	8.04
        /// O	7.60
        /// I	7.26
        /// N	7.09
        /// S	6.54
        /// R	6.12
        /// H	5.49
        /// L	4.14
        /// D	3.99
        /// C	3.06
        /// U	2.71
        /// M	2.53
        /// F	2.30
        /// P	2.00
        /// G	1.96
        /// W	1.92
        /// Y	1.73
        /// B	1.54
        /// V	0.99
        /// K	0.67
        /// X	0.19
        /// J	0.16
        /// Q	0.11
        /// Z	0.09
        /// </summary>
        /// <param name="cipher"></param>
        /// <returns>Plain text</returns> 
        public string AnalyseUsingCharFrequency(string cipher)
        {
            string plainText = "";

            string order = "ZQJXKVBYWGPFMUCDLHRSNIOATE".ToLower();       

            pair[] frequency = new pair[26];
            char[] map = new char[26];

            for (int i = 0; i < 26; i++) frequency[i].y = i;

            foreach (char ch in cipher){
                frequency[ch - 'A'].x ++;
            }
            Array.Sort(frequency, (X, Y) => X.x.CompareTo(Y.x));
            for (int i = 0; i < 26; i++){
                map[frequency[i].y] = order[i];
            }

            foreach (char ch in cipher){
                plainText += map[ch - 'A'];
            }
            return plainText;
        }
    }
}