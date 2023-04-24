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
        static string[,] Sbox = {
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
        static string[,] IsBox = {
            {"52","09","6a","d5","30","36","a5","38","bf","40","a3","9e","81","f3","d7","fb"},
            {"7c","e3","39","82","9b","2f","ff","87","34","8e","43","44","c4","de","e9","cb"},
            {"54","7b","94","32","a6","c2","23","3d","ee","4c","95","0b","42","fa","c3","4e"},
            {"08","2e","a1","66","28","d9","24","b2","76","5b","a2","49","6d","8b","d1","25"},
            {"72","f8","f6","64","86","68","98","16","d4","a4","5c","cc","5d","65","b6","92"},
            {"6c","70","48","50","fd","ed","b9","da","5e","15","46","57","a7","8d","9d","84"},
            {"90","d8","ab","00","8c","bc","d3","0a","f7","e4","58","05","b8","b3","45","06"},
            {"d0","2c","1e","8f","ca","3f","0f","02","c1","af","bd","03","01","13","8a","6b"},
            {"3a","91","11","41","4f","67","dc","ea","97","f2","cf","ce","f0","b4","e6","73"},
            {"96","ac","74","22","e7","ad","35","85","e2","f9","37","e8","1c","75","df","6e"},
            {"47","f1","1a","71","1d","29","c5","89","6f","b7","62","0e","aa","18","be","1b"},
            {"fc","56","3e","4b","c6","d2","79","20","9a","db","c0","fe","78","cd","5a","f4"},
            {"1f","dd","a8","33","88","07","c7","31","b1","12","10","59","27","80","ec","5f"},
            {"60","51","7f","a9","19","b5","4a","0d","2d","e5","7a","9f","93","c9","9c","ef"},
            {"a0","e0","3b","4d","ae","2a","f5","b0","c8","eb","bb","3c","83","53","99","61"},
            {"17","2b","04","7e","ba","77","d6","26","e1","69","14","63","55","21","0c","7d"}};

        static string[,] Rcon = {
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

        static string[,] C = {
            {"02","03","01","01"},
            {"01","02","03","01"},
            {"01","01","02","03"},
            {"03","01","01","02"}
        };
        static string[,] IC = {
            {"0E","0B", "0D", "09"},
            {"09","0E", "0B", "0D"},
            {"0D","09", "0E", "0B"},
            {"0B","0D", "09", "0E"}
            };

        static string toHexa(string number)
        {
            string hx = Convert.ToInt32(number, 2).ToString("X");
            return (hx.Length < 2 ? "0" : "") + hx;
        }
        static string toBinary(string number)
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
        static int toDecimal(string number, int bas)
        {
            return Convert.ToInt32(number, bas);
        }
           
        static string[] getRowAt(string[,] M, int index)
        {
            string[] row = new string[4];
            for (int i = 0; i < 4; i++)
                row[i] = M[index, i];
            return row;
        }   
        static string[] getColAt(string[,] M, int index)
        {
            string[] col = new string[4];
            for (int i = 0; i < 4; i++)
                col[i] = M[i, index];
            return col;
        }
           
        static string xor(string a, string b)
        {
            string ans = "";
            a = toBinary(a);
            b = toBinary(b);
            for (int i = 0; i < a.Length; i++)
                ans += (a[i] == b[i] ? '0' : '1');
            
            return toHexa(ans);
        }
        static void xor(string[] v1, string[] v2)
        {
            for (int i = 0; i < 4; i++)
                v1[i] = xor(v1[i], v2[i]);
        }
        static void xor(string[,] M1, string[,] M2, string[,] res)
        {
            for (int i = 0; i < 4; i++)
                for (int j = 0; j < 4; j++)
                    res[i, j] = xor(M1[i, j], M2[i, j]);
        }
        
        static void fillMatrix(string content, string[,] matrix)
        {
            int k = 0;
            for (int i = 0; i < 4; i++)
                for (int j = 0; j < 4; j++)
                    matrix[j, i] = "" + content[k++] + content[k++];
        }

        static void matrixXORmatrix(string[,] M1, string[,] M2, string[,] res)
        {
            for (int i = 0; i < 4; i++)
                for (int j = 0; j < 4; j++)
                    res[i, j] = xor(M1[i, j], M2[i, j]);
        }

        static void copyMatrixTo(string[,] M1, string[,] M2)
        {
            for (int i = 0; i < 4; i++)
                for (int j = 0; j < 4; j++)
                    M2[i, j] = M1[i, j];
        }

        static void subBytes(string[,] M)
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
        static void IsubBytes(string[,] M)
        {
            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    string val = M[i, j];

                    int r = toDecimal(val[0] + "", 16);
                    int c = toDecimal(val[1] + "", 16);

                    M[i, j] = IsBox[r, c];
                }
            }
        }

        static void ShiftRows(string[,] M)
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
        
        static void IShiftRows(string[,] matrix)
        {
            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < i; j++)
                {
                    string temp = matrix[i, 3];
                    matrix[i, 3] = matrix[i, 2];
                    matrix[i, 2] = matrix[i, 1];
                    matrix[i, 1] = matrix[i, 0];
                    matrix[i, 0] = temp;
                }
            }
        }

        static void mixColumns(string[,] M)
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

            copyMatrixTo(R, M);
        }
        static string[,] IMixColumns(string[,] matrix)
        {
            string[,] res = new string[4, 4];

            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {

                    var x = GMul(Convert.ToByte("0x" + IC[i, 0], 16), Convert.ToByte("0x" + matrix[0, j], 16)) ^
                        GMul(Convert.ToByte("0x" + IC[i, 1], 16), Convert.ToByte("0x" + matrix[1, j], 16)) ^
                        GMul(Convert.ToByte("0x" + IC[i, 2], 16), Convert.ToByte("0x" + matrix[2, j], 16)) ^
                        GMul(Convert.ToByte("0x" + IC[i, 3], 16), Convert.ToByte("0x" + matrix[3, j], 16));
                    if (x.ToString("X").Length == 1)
                    {
                        res[i, j] = "0" + x.ToString("X").ToLower();
                    }
                    else
                    {
                        res[i, j] = x.ToString("X").ToLower();
                    }

                }
            }
            return res;
        }

        static void generateNewKey(string[,] oldkey, int round)
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

                    xor(column, lastcolumn);
                    xor(column, rcon);

                }
                else if (col == 1)
                {
                    string[] w0 = getColAt(newKey, col - 1);
                    xor(column, w0);
                }
                else if (col == 2)
                {
                    string[] w1 = getColAt(newKey, col - 1);
                    xor(column, w1);
                }
                else
                {
                    string[] w2 = getColAt(newKey, col - 1);
                    xor(column, w2);
                }

                for (int i = 0; i < 4; i++)
                    newKey[i, col] = column[i];
            }

            copyMatrixTo(newKey, oldkey);
        }

        public static byte GMul(Byte a, Byte b)
        {
            byte p = 0;
            byte counter;
            byte hi_bit_set;
            for (counter = 0; counter < 8; counter++)
            {
                if ((b & 1) != 0)
                {
                    p ^= a;
                }
                hi_bit_set = (byte)(a & 0x80);
                a <<= 1;
                if (hi_bit_set != 0)
                {
                    a ^= 0x1b;
                }
                b >>= 1;
            }
            return p;
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
                currentCipher = new string[4, 4],
                helperTemp = new string[4, 4]; ;

            fillMatrix(plainText, PLAINTEXT);
            fillMatrix(key, KEY);

            xor(KEY, PLAINTEXT, currentCipher);

            for (int round = 0; round < 10; round++)
            {
                subBytes(currentCipher);
                ShiftRows(currentCipher);
                
                if (round != 9)
                    mixColumns(currentCipher);

                generateNewKey(KEY, round);

                xor(KEY, currentCipher, helperTemp);

                copyMatrixTo(helperTemp, currentCipher);
            }

            for (int i = 0; i < 4; i++)
                for (int j = 0; j < 4; j++)
                    cipherText += currentCipher[j, i];

            return "0x" + cipherText;
        }
        
        public override string Decrypt(string cipherText, string key)
        {
            //throw new NotImplementedException();
            string plainText = "";
            cipherText = cipherText.Substring(2);
            key = key.Substring(2);

            string[,]
                CIPHERTEXT = new string[4, 4],
                KEY = new string[4, 4],
                xor_res = new string[4, 4];

            fillMatrix(cipherText, CIPHERTEXT);
            fillMatrix(key, KEY);


            string[,]
                key0 = new string[4, 4],
                key1 = new string[4, 4],
                key2 = new string[4, 4],
                key3 = new string[4, 4],
                key4 = new string[4, 4],
                key5 = new string[4, 4],
                key6 = new string[4, 4],
                key7 = new string[4, 4],
                key8 = new string[4, 4],
                key9 = new string[4, 4],
                key10 = new string[4, 4];


            // GENERATE ALL KEYS 
            copyMatrixTo(KEY, key0);
            generateNewKey(KEY, 0);
            copyMatrixTo(KEY, key1);

            generateNewKey(KEY, 1);
            copyMatrixTo(KEY, key2);

            generateNewKey(KEY, 2);
            copyMatrixTo(KEY, key3);

            generateNewKey(KEY, 3);
            copyMatrixTo(KEY, key4);

            generateNewKey(KEY, 4);
            copyMatrixTo(KEY, key5);

            generateNewKey(KEY, 5);
            copyMatrixTo(KEY, key6);

            generateNewKey(KEY, 6);
            copyMatrixTo(KEY, key7);

            generateNewKey(KEY, 7);
            copyMatrixTo(KEY, key8);

            generateNewKey(KEY, 8);
            copyMatrixTo(KEY, key9);

            generateNewKey(KEY, 9);
            copyMatrixTo(KEY, key10);


            matrixXORmatrix(key10, CIPHERTEXT, xor_res);

            for (int round = 9; round >= 0; round--)
            {
                IShiftRows(xor_res);
                IsubBytes(xor_res);

                string[,] help = new string[4, 4];
                string[,] curkey = new string[4, 4];

                switch (round)
                {
                    case 1:
                        copyMatrixTo(key1, curkey);
                        break;
                    case 2:
                        copyMatrixTo(key2, curkey);
                        break;
                    case 3:
                        copyMatrixTo(key3, curkey);
                        break;
                    case 4:
                        copyMatrixTo(key4, curkey);
                        break;
                    case 5:
                        copyMatrixTo(key5, curkey);
                        break;
                    case 6:
                        copyMatrixTo(key6, curkey);
                        break;
                    case 7:
                        copyMatrixTo(key7, curkey);
                        break;
                    case 8:
                        copyMatrixTo(key8, curkey);
                        break;
                    case 9:
                        copyMatrixTo(key9, curkey);
                        break;
                    case 0:
                        copyMatrixTo(key0, curkey);
                        break;
                }

                matrixXORmatrix(curkey, xor_res, help);

                copyMatrixTo(help, xor_res);

                if (round != 0)
                    xor_res = IMixColumns(xor_res);
            }

            for (int i = 0; i < 4; i++)
                for (int j = 0; j < 4; j++)
                    plainText += xor_res[j, i];

            return "0x" + plainText;

        }
    }
}