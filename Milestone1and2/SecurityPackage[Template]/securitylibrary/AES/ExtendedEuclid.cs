using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.AES
{
    public class ExtendedEuclid
    {
        /// <summary>
        /// 
        /// </summary>
        /// <param name="number"></param>
        /// <param name="baseN"></param>
        /// <returns>Mul inverse, -1 if no inv</returns>
        public int GetMultiplicativeInverse(int number, int baseN)
        {
            int q, a, b, r, t1, t2, t;

            a = baseN;
            b = number;

            if (relativelyPrime(a, b) == false)
            {
                t2 = -1;
            }
            else
            {
                t1 = 0;
                t2 = 1;
                q = a / b;
                r = a % b;
                t = t1 - t2 * q;
                while (r != 0)
                {
                    a = b;
                    b = r;
                    t1 = t2;
                    t2 = t;

                    q = a / b;
                    r = a % b;
                    t = t1 - t2 * q;

                }
                if (t2 < 0)
                {
                    t2 = baseN + t2;
                }
            }
            return t2;

        }

        public static int gcd(int a, int b)
        {
            int t;
            if (b < a)
            {
                t = b;
                b = a;
                a = t;
            }
            while (b != 0)
            {
                t = a;
                a = b;
                b = t % b;
            }
            return a;
        }
        public static bool relativelyPrime(int a, int b)
        {
            return gcd(a, b) == 1;
        }
    }
}