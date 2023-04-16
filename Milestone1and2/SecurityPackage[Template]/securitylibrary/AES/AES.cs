using Microsoft.Win32.SafeHandles;
using System;
using System.Collections.Generic;
using System.Data;
using System.Globalization;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.AES
{
    /// <summary>
    /// If the string starts with 0x.... then it's Hexadecimal not string
    /// </summary>
    public class AES : CryptographicTechnique
    {
        string[,] Sbox = {
            { "63",  "7C",  "77", "7B", "F2",  "6b",  "6f",  "c5",  "30",  "01",  "67",  "2b",  "fe",  "d7",  "ab",  "76" },
            { "cA",  "82",  "C9", "7D", "FA",  "59",  "47",  "f0",  "ad",  "d4",  "a2",  "af",  "9c",  "a4",  "72",  "c0" },
            { "B7",  "FD",  "93", "26", "36",  "3f",  "f7",  "cc",  "34",  "a5",  "e5",  "f1",  "71",  "d8",  "31",  "15" },
            { "04",  "C7",  "23", "C3", "18",  "96",  "05",  "9a",  "07",  "12",  "80",  "e2",  "eb",  "27",  "b2",  "75" },
            { "09",  "83",  "2C", "1A", "1B",  "6e",  "5a",  "a0",  "52",  "3b",  "d6",  "b3",  "29",  "e3",  "2f",  "84" },
            { "53",  "D1",  "00", "ED", "20",  "fc",  "b1",  "5b",  "6a",  "cb",  "be",  "39",  "4a",  "4c",  "58",  "cf" },
            { "D0",  "EF",  "AA", "FB", "43",  "4d",  "33",  "85",  "45",  "f9",  "02",  "7f",  "50",  "3c",  "9f",  "a8" },
            { "51",  "A3",  "40", "8F", "92",  "9d",  "38",  "f5",  "bc",  "b6",  "da",  "21",  "10",  "ff",  "f3",  "d2" },
            { "cD",  "0C",  "13", "EC", "5F",  "97",  "44",  "17",  "c4",  "a7",  "7e",  "3d",  "64",  "5d",  "19",  "73" },
            { "60",  "81",  "4F", "DC", "22",  "2a",  "90",  "88",  "46",  "ee",  "b8",  "14",  "de",  "5e",  "0b",  "db" },
            { "E0",  "32",  "3A", "0A", "49",  "06",  "24",  "5c",  "c2",  "d3",  "ac",  "62",  "91",  "95",  "e4",  "79" },
            { "E7",  "C8",  "37", "6D", "8D",  "d5",  "4e",  "a9",  "6c",  "56",  "f4",  "ea",  "65",  "7a",  "ae",  "08" },
            { "BA",  "78",  "25", "2E", "1C",  "a6",  "b4",  "c6",  "e8",  "dd",  "74",  "1f",  "4b",  "bd",  "8b",  "8a" },
            { "70",  "3E",  "B5", "66", "48",  "03",  "f6",  "0e",  "61",  "35",  "57",  "b9",  "86",  "c1",  "1d",  "9e" },
            { "E1",  "F8",  "98", "11", "69",  "d9",  "8e",  "94",  "9b",  "1e",  "87",  "e9",  "ce",  "55",  "28",  "df" },
            { "8C",  "A1",  "89", "0D", "BF",  "e6",  "42",  "68",  "41",  "99",  "2d",  "0f",  "b0",  "54",  "bb",  "16" },
        };
        
        string[,] Rcon = {
            {"01","00","00","00"}, // 0
            {"02","00","00","00"}, // 1
            {"04","00","00","00"}, // 2
            {"08","00","00","00"}, // 3
            {"10","00","00","00"}, // 4
            {"20","00","00","00"}, // 5
            {"40","00","00","00"}, // 6
            {"80","00","00","00"}, // 7
            {"1B","00","00","00"}, // 8
            {"36","00","00","00"}, // 9
        
        };
        
        string[,] C = {
            {"02","03","01","01"},
            {"01","02","03","01"},
            {"01","01","02","03"},
            {"03","01","01","02"}
        };

        int toDecimal(string number, int bas)
        {
            return Convert.ToInt32(number, bas);
        }

        string toHexa(string number)
        {
            string hx = Convert.ToInt32(number, 2).ToString("X");
            return (hx.Length < 2 ? "0" : "") + hx;
        }
        
        string toBinary(string number)
        {
            return String.Join(
                String.Empty, 
                number.Select(
                    c => Convert.ToString(
                        Convert.ToInt32(
                            c.ToString(), 
                            16), 
                        2).PadLeft(4, '0')));
        }
        
        void VectorXorVector(string[] v1, string[] v2)
        {
            for (int i = 0; i < 4; i++)
                v1[i] = xor(v1[i], v2[i]);
        }
        
        string[] getRowAt(string[,] M, int index)
        {
            string[] row = new string[4];
            for (int i = 0; i < 4; i++)
                row[i] = M[index, i];
            return row;
        }
        
        string[] getColAt(string[,] M, int index)
        {
            string[] col = new string[4];
            for (int i = 0; i < 4; i++)
                col[i] = M[i, index];
            return col;
        }
        
        void fillMatrix(string content, string[,] matrix)
        {
            int k = 0;
            for (int i = 0; i < 4; i++)
                for (int j = 0; j < 4; j++)
                    matrix[j, i] = "" + content[k++] + content[k++];
        }
        
        string xor(string a, string b)
        {
            string ans = "";
            a = toBinary(a);
            b = toBinary(b);
            for (int i = 0; i < a.Length; i++)
                ans += (a[i] == b[i] ? '0' : '1');
            
            return toHexa(ans);
        }
        
        void matrixXORmatrix(string[,] M1, string[,] M2, string[,] res)
        {
            for (int i = 0; i < 4; i++)
                for (int j = 0; j < 4; j++)
                    res[i, j] = xor(M1[i, j], M2[i, j]);
        }
        
        void subBytes(string[,] M)
        {
            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    string val = M[i, j];

                    int r = toDecimal(val[0] + "", 16);
                    int c = toDecimal(val[1] + "", 16);

                    M[i, j] = Sbox[r, c];
                }
            }
        }
        
        void ShiftRows(string[,] M)
        {
            string[] row = new string[4];
            for (int i = 0; i < 4; i++)
            {
                for (int j = i; j < 4; j++)
                    row[j - i] = M[i, j];
                
                for (int j = 0; j < i; j++)
                    row[4 - i + j] = M[i, j];
                
                for (int j = 0; j < 4; j++)
                    M[i, j] = row[j];
            }
        }
        
        void mixColumns(string[,] M)
        {
            string[,] R = new string[4, 4]{
                {"-1","-1","-1", "-1"},
                {"-1","-1","-1", "-1"},
                {"-1","-1","-1", "-1"},
                {"-1","-1","-1", "-1"},
            };

            for (int i = 0; i < 4; i++)
            {
                string[] a = new string[4];
                for (int j = 0; j < 4; j++)
                {
                    for (int k = 0; k < 4; k++)
                    {
                        string b1 = toBinary(M[k, j]), res = "";

                        if (C[i, k] == "01")
                        {
                            res = toHexa(b1);
                        }
                        else if (C[i, k] == "02")
                        {
                            if (b1[0] == '0')
                            {
                                res = toHexa(b1.Substring(1) + "0");
                            }
                            else
                            {
                                res = toHexa(b1.Substring(1) + "0");
                                res = xor(res, "1B");
                            }
                        }
                        else
                        {
                            if (b1[0] == '0')
                            {
                                res = toHexa(b1.Substring(1) + "0");
                            }
                            else
                            {
                                res = toHexa(b1.Substring(1) + "0");
                                res = xor(res, "1B");
                            }

                            res = xor(res, toHexa(b1));
                        }
                        if (R[i, j] == "-1")
                        {
                            R[i, j] = res;
                        }
                        else
                        {
                            R[i, j] = xor(R[i, j], res);
                        }
                    }
                }
            }

            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                    M[i, j] = R[i, j];
            }

        }
        
        void generateNewKey(string[,] oldkey, int round)
        {
            string[,] newKey = new string[4, 4];
            string[] rcon = getRowAt(Rcon, round);

            for (int col = 0; col < 4; col++)
            {
                string[] column = getColAt(oldkey, col);
                if (col == 0)
                {
                    string[] lastcolumn = getColAt(oldkey, 3);

                    string val = lastcolumn[0];
                    for (int i = 0; i < 3; i++)
                        lastcolumn[i] = lastcolumn[i + 1];

                    lastcolumn[3] = val;

                    for (int i = 0; i < 4; i++)
                    {
                        string value = lastcolumn[i];
                        int r = toDecimal(value[0] + "", 16);
                        int c = toDecimal(value[1] + "", 16);
                        lastcolumn[i] = Sbox[r, c];
                    }

                    VectorXorVector(column, lastcolumn);
                    VectorXorVector(column, rcon);

                }
                else if (col == 1)
                {
                    string[] w0 = getColAt(newKey, col - 1);
                    VectorXorVector(column, w0);
                }
                else if (col == 2)
                {
                    string[] w1 = getColAt(newKey, col - 1);
                    VectorXorVector(column, w1);
                }
                else
                {
                    string[] w2 = getColAt(newKey, col - 1);
                    VectorXorVector(column, w2);
                }

                for (int i = 0; i < 4; i++)
                    newKey[i, col] = column[i];
            }

            for (int i = 0; i < 4; i++)
                for (int j = 0; j < 4; j++)
                    oldkey[i, j] = newKey[i, j];
        }

        public override string Encrypt(string plainText, string key)
        {
            // throw new NotImplementedException();
            string cipherText = "";
            plainText = plainText.Substring(2);
            key = key.Substring(2);

            string[,] 
                PLAINTEXT = new string[4, 4],
                KEY = new string[4, 4], 
                xor_res = new string[4, 4];

            fillMatrix(plainText, PLAINTEXT);
            fillMatrix(key, KEY);

            matrixXORmatrix(KEY, PLAINTEXT, xor_res);

            for (int round = 0; round < 10; round++)
            {
                subBytes(xor_res);
                ShiftRows(xor_res);
                if (round != 9)
                    mixColumns(xor_res);

                generateNewKey(KEY, round);

                string[,] help = new string[4, 4];

                matrixXORmatrix(KEY, xor_res, help);

                for (int i = 0; i < 4; i++)
                    for (int j = 0; j < 4; j++)
                        xor_res[i, j] = help[i, j];
                
            }

            for (int i = 0; i < 4; i++)
                for (int j = 0; j < 4; j++)
                    cipherText += xor_res[j, i];

            return "0x" + cipherText;
        }
        
        public override string Decrypt(string cipherText, string key)
        {
            throw new NotImplementedException();
        }
    }
}