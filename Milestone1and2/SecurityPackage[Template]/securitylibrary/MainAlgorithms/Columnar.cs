using System;
using System.Collections;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data.SqlClient;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class Columnar : ICryptographicTechnique<string, List<int>>
    {
        string plnTxt, cipherTxt;
        bool RedFlage;
        int ar, c, r;
        Dictionary
            <string, int> exist;

        public string[] createColMatrix(int col)
        {
            string[] matrix = new string[col];

            for (int i = 0; i < col; i++)
                matrix[i] = "";

            for (int i = 0; i < ar; i++)
            {
                if (i < plnTxt.Length)
                    matrix[i % col] += plnTxt[i];
                else break;

                // else matrix[i % col] += '*';

            }


            for (int i = 0; i < col; i++)
            {
                int val;
                if (exist.TryGetValue(matrix[i], out val))
                {
                    exist[matrix[i]] = val + 1;

                }
                else
                    exist.Add(matrix[i], 1);


                //Console.WriteLine(matrix[i]);
            }
            //Console.WriteLine();

            //for (int i = 0; i < r; i++)
            //{
            //    for (int j = 0; j < col; j++)
            //    {
            //        if (i < matrix[j].Length)
            //            Console.Write(matrix[j][i] + " ");
            //    }
            //    Console.WriteLine();
            //}

            return matrix;
        }

        public string[] createRowMatrix(int row, int col)
        {
            string[] matrix = new string[col];

            for (int i = 0; i < col; i++)
                matrix[i] = "";


            int index = 0;
            for (int i = 0; i < cipherTxt.Length;)
            {
                int cnt;

                int end = i + row <= cipherTxt.Length ? row : cipherTxt.Length - i;
                string s1 = cipherTxt.Substring(i, end);


                if (exist.TryGetValue(s1, out cnt))
                {
                    // Console.WriteLine("AAAA");
                    // Console.WriteLine(index);
                    // if(index<col)
                    if (cnt == 0)
                    {
                        s1 = cipherTxt.Substring(i, end - 1);


                        if (exist.TryGetValue(s1, out cnt))
                        {
                            if (cnt == 0)
                            {
                                break;
                            }
                            else
                                matrix[index] += s1;
                            exist[s1]--;

                        }



                        i += end;
                        i--;
                    }
                    else
                    {
                        exist[s1]--;
                    }

                    matrix[index] += s1;
                    i += end;
                }
                else
                {
                    //Console.WriteLine("BBBBBBBBBBB");

                    if (end == row)
                        s1 = cipherTxt.Substring(i, end - 1);
                    else
                    {
                        s1 = cipherTxt.Substring(i, end);
                    }

                    if (exist.TryGetValue(s1, out cnt))
                    {
                        matrix[index] += s1;

                    }
                    i += end;
                    if (end == row) i--;
                }

                index++;

                if (index >= col) break;
            }
            //Console.WriteLine(cipherTxt + " " + index);
            //Console.WriteLine();

            //for (int i = 0; i < col; i++)
            //{
            //    Console.WriteLine(matrix[i]);
            //}

            //Console.WriteLine();

            //for (int i = 0; i < r; i++)
            //{
            //    for (int j = 0; j < col; j++)
            //    {
            //        if (i < matrix[j].Length)
            //            Console.Write(matrix[j][i] + " ");
            //    }

            //    Console.WriteLine();

            //}

            return matrix;
        }

        public List<int> AnalyseCompliler(int row, int col)
        {
            exist = new Dictionary<string, int>();
            List<int> key = new List<int>();
            string[] plainMatrix = createColMatrix(col);
            string[] cipherMatrix = createRowMatrix(row, col);



            bool flage = false;

            for (int i = 0; i < col; i++)
            {
                flage = false;
                for (int j = 0; j < col; j++)
                {
                    if (cipherMatrix[j] == plainMatrix[i])
                    {
                        key.Add(j+1);
                        flage = true;
                    }
                }
                if (!flage)
                {
                    break;
                }
            }


            return flage ? key : null;
        }

        public List<int> Analyse(string plainText, string cipherText)
        {
            // throw new NotImplementedException();
            cipherText = cipherText.ToLower();
            plnTxt = plainText;
            cipherTxt = cipherText;
            if (plainText == cipherText)
            {
                return new List<int> { 1 };
            }

            List<int> key = new List<int>();

            for (int i = 1; i < cipherText.Length; i++)
            {


                int col = i, area = cipherText.Length - (cipherText.Length % i);
                if (cipherText.Length % col != 0)
                {
                    area += i;
                }

                int row = area / col;

                ar = area; r = row; c = col;
                //Console.WriteLine(row+ "x" + col);

                if (ar < cipherText.Length) continue;

                List<int> key_he = AnalyseCompliler(row, col);

                if (key_he != null)
                {
                    key = key_he;
                    return key;
                }
                //break;
            }


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
