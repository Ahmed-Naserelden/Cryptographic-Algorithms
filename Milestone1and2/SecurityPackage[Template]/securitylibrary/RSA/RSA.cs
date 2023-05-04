using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.RSA
{
    public class RSA
    {
        public int Encrypt(int p, int q, int M, int e)
        {
            double n = p * q;


            double cipher = power(M, e, (int)n);


            return (int)cipher;
        }

        public int Decrypt(int p, int q, int C, int e)
        {
            double n = (p - 1) * (q - 1);
            double nTmp = p * q;
            int d = 0;

            for (int i = 1; i < n; i++)
            {
                if ((i * e) % n == 1)
                {
                    d = i;
                    break;
                }
            }
            double cipher = power(C, d, (int)nTmp);


            return (int)cipher;
        }
        public static long power(int Text, int Key, int M)
        {

            if (Key == 0) return 1;
            long res = power(Text, Key / 2, M);
            res = (res * res) % M;
            if (Key % 2 == 1) res = (res * (Text % M)) % M;
            return res;
        }
    }
}
