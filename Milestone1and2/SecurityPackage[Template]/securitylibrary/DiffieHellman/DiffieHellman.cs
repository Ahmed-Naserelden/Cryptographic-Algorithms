using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.DiffieHellman
{
    public class DiffieHellman
    {

        public static int main_calc(int a, int b, int q)
        {
            int res=1;
            for (int i = 0; i < b; i++)
            {
                res *= a ;
                res = calc_mod(res, q);
            }
            return res;
        }

        public static int calc_mod(int a, int b)
        {
            int res;
            return res = a % b;
        }

        public List<int> GetKeys(int q, int alpha, int xa, int xb)
        {
            //throw new NotImplementedException();

            //public keys
            int ya = main_calc(alpha, xa,q); //Ya
            int yb = main_calc(alpha, xb,q); //Yb

            //secret keys
            int K_one = main_calc(yb, xa,q);
            int K_two = main_calc(ya, xb,q);

            List<int> keys = new List<int>();
            keys.Add(K_one);
            keys.Add(K_two);
            return keys;
        }
    }
}