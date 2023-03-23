using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    /// <summary>
    /// The List<int> is row based. Which means that the key is given in row based manner.
    /// </summary>
    public class HillCipher : ICryptographicTechnique<string, string>, ICryptographicTechnique<List<int>, List<int>>
    {
        public List<int> Analyse(List<int> plainText, List<int> cipherText)
        {
            //throw new NotImplementedException();
            int row = 2;
            int[,] cipherMatrix = new int[row, row];
            int[,] plainMatrix = new int[row, row];
            int count = 0;
            for (int i = 0; i < row; i++)
            {
                for (int j = 0; j < row; j++)
                {
                    cipherMatrix[j, i] = cipherText[count];
                    plainMatrix[j, i] = plainText[count];
                    count++;
                }
            }
            int[,] keyMatrix = new int[row, row];
            List<int> key = new List<int>();
            bool exit = true;
            for (int d = 0; d < 26; d++)
            {
                for (int c = 0; c < 26; c++)
                {
                    for (int b = 0; b < 26; b++)
                    {
                        for (int a = 0; a < 26; a++)
                        {
                            keyMatrix[0, 0] = a;
                            keyMatrix[1, 0] = c;
                            keyMatrix[0, 1] = b;
                            keyMatrix[1, 1] = d;

                            int[,] temp = new int[row, row];
                            ////mutiple matrix
                            for (int i = 0; i < row; i++)
                            {
                                for (int j = 0; j < row; j++)
                                {
                                    temp[i, j] = 0;
                                    for (int k = 0; k < row; k++)
                                    {
                                        temp[i, j] += plainMatrix[k, j] * keyMatrix[i, k];
                                    }
                                    temp[i, j] %= 26;


                                }
                            }
                            //check
                            exit = true;
                            for (int i = 0; i < row; i++)
                            {
                                for (int j = 0; j < row; j++)
                                {
                                    if (temp[i, j] != cipherMatrix[i, j])
                                        exit = false;
                                }
                            }


                            if (exit)
                            {
                                for (int j = 0; j < row; j++)
                                {
                                    for (int i = 0; i < row; i++)
                                    {
                                        if (keyMatrix[j, i] < 0)
                                            keyMatrix[j, i] = 26 + keyMatrix[j, i];

                                        Console.WriteLine(keyMatrix[j, i]);
                                        key.Add(keyMatrix[j, i] % 26);
                                    }
                                }
                                return key;
                            }
                        }
                    }
                }
            }
            throw new InvalidAnlysisException();
            // return key;
        }

        public string Analyse(string plainText, string cipherText)
        {
            throw new NotImplementedException();
        }

        public List<int> Decrypt(List<int> cipherText, List<int> key)
        {
            //throw new NotImplementedException();
            int row = (int)Math.Sqrt(key.Count);

            int[,] keyMatrix = new int[row, row];
            int count = 0;
            for (int i = 0; i < row; i++)
            {
                for (int j = 0; j < row; j++)
                {
                    keyMatrix[i, j] = key[count];
                    count++;
                }
            }

            int column = cipherText.Count / row;
            int[,] cipherMatrix = new int[row, column];
            count = 0;
            for (int i = 0; i < column; i++)
            {
                for (int j = 0; j < row; j++)
                {
                    cipherMatrix[j, i] = cipherText[count];
                    count++;
                }
            }

            int det = 0;
            int[,] inverseKey = new int[row, row];
            int[,] finalkey = new int[row, row];
            if (row == 2)
            {
                det = (keyMatrix[0, 0] * keyMatrix[1, 1] - keyMatrix[0, 1] * keyMatrix[1, 0]);
                det %= 26;
                if (det == 0 || det % 2 == 0)
                {
                    throw new Exception();
                }

                (keyMatrix[0, 0], keyMatrix[1, 1]) = (keyMatrix[1, 1], keyMatrix[0, 0]);
                keyMatrix[1, 0] *= -1;
                keyMatrix[0, 1] *= -1;


                for (int i = 0; i < row; i++)
                {
                    for (int j = 0; j < row; j++)
                    {
                        inverseKey[i, j] = det * keyMatrix[i, j];
                    }
                }

            }
            else
            {
                det = keyMatrix[0, 0] * (keyMatrix[1, 1] * keyMatrix[2, 2] - keyMatrix[1, 2] * keyMatrix[2, 1])
                    - keyMatrix[0, 1] * (keyMatrix[1, 0] * keyMatrix[2, 2] - keyMatrix[2, 0] * keyMatrix[1, 2])
                    + keyMatrix[0, 2] * (keyMatrix[2, 1] * keyMatrix[1, 0] - keyMatrix[1, 1] * keyMatrix[2, 0]);
                det %= 26;
                if (det == 0)
                {
                    throw new Exception();
                }
                else if (det < 0)
                {
                    det = 26 + det;
                }

                for (int i = 1; i < det; i++)
                {
                    if ((i * det) % 26 == 1)
                    {
                        det = i; break;
                    }
                }

                int[,] D = new int[row, row];
                D[0, 0] = (keyMatrix[1, 1] * keyMatrix[2, 2] - keyMatrix[1, 2] * keyMatrix[2, 1]);
                D[0, 1] = (keyMatrix[1, 0] * keyMatrix[2, 2] - keyMatrix[1, 2] * keyMatrix[2, 0]);
                D[0, 2] = (keyMatrix[1, 0] * keyMatrix[2, 1] - keyMatrix[1, 1] * keyMatrix[2, 0]);

                D[1, 0] = (keyMatrix[0, 1] * keyMatrix[2, 2] - keyMatrix[0, 2] * keyMatrix[2, 1]);
                D[1, 1] = (keyMatrix[0, 0] * keyMatrix[2, 2] - keyMatrix[0, 2] * keyMatrix[2, 0]);
                D[1, 2] = (keyMatrix[0, 0] * keyMatrix[2, 1] - keyMatrix[0, 1] * keyMatrix[2, 0]);

                D[2, 0] = (keyMatrix[0, 1] * keyMatrix[1, 2] - keyMatrix[0, 2] * keyMatrix[1, 1]);
                D[2, 1] = (keyMatrix[0, 0] * keyMatrix[1, 2] - keyMatrix[0, 2] * keyMatrix[1, 0]);
                D[2, 2] = (keyMatrix[0, 0] * keyMatrix[1, 1] - keyMatrix[0, 1] * keyMatrix[1, 0]);

                for (int i = 0; i < row; i++)
                {
                    for (int j = 0; j < row; j++)
                    {
                        inverseKey[j, i] = (int)((Math.Pow(-1, i + j) * det * D[i, j]) % 26);
                        if (inverseKey[i, j] < 0)
                            inverseKey[i, j] = 26 + inverseKey[i, j];

                    }
                }

            }

            int[,] plainMatrix = new int[row, column];
            for (int i = 0; i < row; i++)
            {
                for (int j = 0; j < column; j++)
                {
                    plainMatrix[i, j] = 0;
                    for (int k = 0; k < row; k++)
                    {
                        plainMatrix[i, j] = plainMatrix[i, j] + cipherMatrix[k, j] * inverseKey[i, k];
                    }

                    plainMatrix[i, j] %= 26;
                }


            }

            List<int> plainText = new List<int>();

            for (int j = 0; j < column; j++)
            {
                for (int i = 0; i < row; i++)
                {
                    if (plainMatrix[i, j] < 0)
                        plainMatrix[i, j] = 26 + plainMatrix[i, j];
                    plainText.Add(plainMatrix[i, j] % 26);
                }
            }

            return plainText;
        }
        public string Decrypt(string cipherText, string key)
        {
            throw new NotImplementedException();
        }

        public List<int> Encrypt(List<int> plainText, List<int> key)
        {

            int rows = (int)Math.Sqrt(key.Count);
            int[,] keyMatrix = new int[rows, rows];
            int count = 0;
            for (int i = 0; i < rows; i++)
            {
                for (int j = 0; j < rows; j++)
                {
                    keyMatrix[i, j] = key[count];
                    count++;
                }
            }
            count = 0;
            int columns = plainText.Count / rows;
            int[,] plainMatrix = new int[rows, columns];
            for (int i = 0; i < columns; i++)
            {
                for (int j = 0; j < rows; j++)
                {
                    plainMatrix[j, i] = plainText[count];
                    count++;
                }
            }

            int[,] cipherMatrix = new int[rows, columns];

            for (int i = 0; i < rows; i++)
            {
                for (int j = 0; j < columns; j++)
                {
                    cipherMatrix[i, j] = 0;
                    for (int k = 0; k < rows; k++)
                    {
                        cipherMatrix[i, j] = cipherMatrix[i, j] + plainMatrix[k, j] * keyMatrix[i, k];

                    }
                    cipherMatrix[i, j] %= 26;
                }
            }

            List<int> cipherText = new List<int>();

            for (int j = 0; j < columns; j++)
            {
                for (int i = 0; i < rows; i++)
                {
                    cipherText.Add(cipherMatrix[i, j]);
                }
            }
            return cipherText;
        }

        public string Encrypt(string plainText, string key)
        {
            throw new NotImplementedException();
        }

        public List<int> Analyse3By3Key(List<int> plain3, List<int> cipher3)
        {
            //throw new NotImplementedException();
            int row = 3;
            int[,] cipherMatrix = new int[row, row];
            int[,] plainMatrix = new int[row, row];
            int count = 0;
            for (int i = 0; i < row; i++)
            {
                for (int j = 0; j < row; j++)
                {
                    cipherMatrix[i, j] = cipher3[count];
                    plainMatrix[i, j] = plain3[count];
                    count++;
                }
            }
            int det = 0;
            det = plainMatrix[0, 0] * (plainMatrix[1, 1] * plainMatrix[2, 2] - plainMatrix[1, 2] * plainMatrix[2, 1])
                   - plainMatrix[0, 1] * (plainMatrix[1, 0] * plainMatrix[2, 2] - plainMatrix[2, 0] * plainMatrix[1, 2])
                   + plainMatrix[0, 2] * (plainMatrix[2, 1] * plainMatrix[1, 0] - plainMatrix[1, 1] * plainMatrix[2, 0]);
            det %= 26;
            if (det == 0)
            {
                throw new Exception();
            }
            else if (det < 0)
            {
                det = 26 + det;
            }
            for (int i = 1; ; i++)
            {
                if ((i * det) % 26 == 1)
                {
                    det = i; break;
                }
            }
            int[,] D = new int[row, row];
            D[0, 0] = (plainMatrix[1, 1] * plainMatrix[2, 2] - plainMatrix[1, 2] * plainMatrix[2, 1]);
            D[0, 1] = (plainMatrix[1, 0] * plainMatrix[2, 2] - plainMatrix[1, 2] * plainMatrix[2, 0]);
            D[0, 2] = (plainMatrix[1, 0] * plainMatrix[2, 1] - plainMatrix[1, 1] * plainMatrix[2, 0]);

            D[1, 0] = (plainMatrix[0, 1] * plainMatrix[2, 2] - plainMatrix[0, 2] * plainMatrix[2, 1]);
            D[1, 1] = (plainMatrix[0, 0] * plainMatrix[2, 2] - plainMatrix[0, 2] * plainMatrix[2, 0]);
            D[1, 2] = (plainMatrix[0, 0] * plainMatrix[2, 1] - plainMatrix[0, 1] * plainMatrix[2, 0]);

            D[2, 0] = (plainMatrix[0, 1] * plainMatrix[1, 2] - plainMatrix[0, 2] * plainMatrix[1, 1]);
            D[2, 1] = (plainMatrix[0, 0] * plainMatrix[1, 2] - plainMatrix[0, 2] * plainMatrix[1, 0]);
            D[2, 2] = (plainMatrix[0, 0] * plainMatrix[1, 1] - plainMatrix[0, 1] * plainMatrix[1, 0]);

            int[,] inverseplain = new int[row, row];
            for (int i = 0; i < row; i++)
            {
                for (int j = 0; j < row; j++)
                {
                    inverseplain[j, i] = (int)((Math.Pow(-1, i + j) * det * D[i, j]) % 26);
                    if (inverseplain[i, j] < 0)
                        inverseplain[i, j] = 26 + inverseplain[i, j];

                }
            }
            int[,] keyMatrix = new int[row, row];
            for (int i = 0; i < row; i++)
            {
                for (int j = 0; j < row; j++)
                {
                    keyMatrix[i, j] = 0;
                    for (int k = 0; k < row; k++)
                    {
                        keyMatrix[i, j] += cipherMatrix[k, j] * inverseplain[i, k];
                    }
                    keyMatrix[i, j] %= 26;
                    if (keyMatrix[i, j] < 0)
                        keyMatrix[i, j] = 26 + keyMatrix[i, j];
                }


            }



            List<int> key = new List<int>();

            for (int i = 0; i < row; i++)
            {
                for (int j = 0; j < row; j++)
                {
                    if (keyMatrix[j, i] < 0)
                        keyMatrix[j, i] = 26 + keyMatrix[j, i];
                    Console.WriteLine(keyMatrix[j, i]);
                    key.Add(keyMatrix[j, i] % 26);
                }
            }
            return key;

        }

        public string Analyse3By3Key(string plain3, string cipher3)
        {
            throw new NotImplementedException();
        }
    }
}
