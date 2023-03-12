using System;
using System.Collections.Generic;
using System.Data.SqlClient;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class Columnar : ICryptographicTechnique<string, List<int>>
    {
        public List<int> Analyse(string plainText, string cipherText)
        {
            // throw new NotImplementedException();
            cipherText = cipherText.ToLower();
            List<int> key = new List<int>();



            
            return key;
        }

        public string Decrypt(string cipherText, List<int> key)
        {
           // throw new NotImplementedException();
            string plainText = "";
            
            int numOfCols = key.Count;

            int numOfRows = (int)Math.Ceiling((double)cipherText.Length / numOfCols);

            char[,] matrix = new char[numOfRows, numOfCols];

            int[] arr = new int[numOfCols];

            for (int i = 0; i < key.Count; i++)
            {
                arr[key[i] /* 1-base */ - 1] = i;
            }

            int index = 0;
            
            for(int i = 0; i < numOfCols; i++)
            {
                for(int j = 0; j < numOfRows; j++)
                {
                    matrix[j, arr[i]] = index < cipherText.Length ? cipherText[index++] : 'x';
                }
            }



            for (int i = 0; i < numOfRows; i++)
            {
                for (int j = 0; j < numOfCols; j++)
                {
                    //if (matrix[i, j ]!= '*')
                        plainText += matrix[i, j];
                }
            }

            return plainText.ToLower();
        }

        public string Encrypt(string plainText, List<int> key)
        {
            // throw new NotImplementedException();
            string cipherText = "";

            int numOfCols = key.Count;

            int numOfRows = (int) Math.Ceiling((double) plainText.Length / numOfCols);

            char[,] matrix = new char[numOfRows, numOfCols];

            int index = 0;
            for(int i = 0; i < numOfRows; i++)
            {
                for(int j = 0; j < numOfCols; j++)
                {
                    matrix[i, j] = index < plainText.Length ? plainText[index++] : 'x';
                }
            }

            int[] arr = new int[numOfCols];

            for (int i = 0; i < key.Count; i++)
            {
                arr[key[i] /* 1-base */ - 1] = i;
            }


            for (int i = 0; i < numOfCols; i++)
            {
                for(int j = 0; j < numOfRows; j++)
                {
                    /*if(matrix[j, arr[i]] != '*')*/ cipherText += matrix[j, arr[i]];
                }
            }

            return cipherText.ToUpper();
        }
    }
}
