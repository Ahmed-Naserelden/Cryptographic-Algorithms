using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.DES
{
    /// <summary>
    /// If the string starts with 0x.... then it's Hexadecimal not string
    /// </summary>
    public class DES : CryptographicTechnique
    {
        public static int[] pc1 = {
                                  57,49,41,33,25,17,9,
                                  1,58,50,42,34,26,18,
                                  10,2,59,51,43,35,27,
                                  19,11,3,60,52,44,36,
                                  63,55,47,39,31,23,15,
                                  7,62,54,46,38,30,22,
                                  14,6,61,53,45,37,29,
                                  21,13,5,28,20,12,4
                                  };

        public static int[] pc2 = {
                                  14,17,11,24,1,5,
                                  3,28,15,6,21,10,
                                  23,19,12,4,26,8,
                                  16,7,27,20,13,2,
                                  41,52,31,37,47,55,
                                  30,40,51,45,33,48,
                                  44,49,39,56,34,53,
                                  46,42,50,36,29,32
                                  };
        public static int[] IP = {
                    58,50,42,34,26,18,10,2,
                    60,52,44,36,28,20,12,4,
                    62,54,46,38,30,22,14,6,
                    64,56,48,40,32,24,16,8,
                    57,49,41,33,25,17,9,1,
                    59,51,43,35,27,19,11,3,
                    61,53,45,37,29,21,13,5,
                    63,55,47,39,31,23,15,7
                    };
        public static int[] eTable = {
                        32,1,2,3,4,5,4,5,
                        6,7,8,9,8,9,10,11,
                        12,13,12,13,14,15,16,17,
                        16,17,18,19,20,21,20,21,
                        22,23,24,25,24,25,26,27,
                        28,29,28,29,30,31,32,1
                        };

        public static int[,,] sBox = new int[8, 4, 16]
        {
        {
            {14,4,13,1,2,15,11,8,3,10,6,12,5,9,0,7 },
            { 0,15,7,4,14,2,13,1,10,6,12,11,9,5,3,8},
            { 4,1,14,8,13,6,2,11,15,12,9,7,3,10,5,0 },
            { 15,12,8,2,4,9,1,7,5,11,3,14,10,0,6,13 }
        },
        {
            { 15,1,8,14,6,11,3,4,9,7,2,13,12,0,5,10 },
            { 3,13,4,7,15,2,8,14,12,0,1,10,6,9,11,5},
            { 0,14,7,11,10,4,13,1,5,8,12,6,9,3,2,15 },
            { 13,8,10,1,3,15,4,2,11,6,7,12,0,5,14,9 }
        },
        {
            { 10,0,9,14,6,3,15,5,1,13,12,7,11,4,2,8 },
            { 13,7,0,9,3,4,6,10,2,8,5,14,12,11,15,1},
            { 13,6,4,9,8,15,3,0,11,1,2,12,5,10,14,7 },
            { 1,10,13,0,6,9,8,7,4,15,14,3,11,5,2,12 }
        },
        {
            { 7,13,14,3,0,6,9,10,1,2,8,5,11,12,4,15 },
            { 13,8,11,5,6,15,0,3,4,7,2,12,1,10,14,9},
            { 10,6,9,0,12,11,7,13,15,1,3,14,5,2,8,4 },
            { 3,15,0,6,10,1,13,8,9,4,5,11,12,7,2,14 }
        },
        {
            { 2,12,4,1,7,10,11,6,8,5,3,15,13,0,14,9 },
            { 14,11,2,12,4,7,13,1,5,0,15,10,3,9,8,6},
            { 4,2,1,11,10,13,7,8,15,9,12,5,6,3,0,14 },
            { 11,8,12,7,1,14,2,13,6,15,0,9,10,4,5,3 }
        },
        {
            { 12,1,10,15,9,2,6,8,0,13,3,4,14,7,5,11 },
            { 10,15,4,2,7,12,9,5,6,1,13,14,0,11,3,8},
            { 9,14,15,5,2,8,12,3,7,0,4,10,1,13,11,6 },
            { 4,3,2,12,9,5,15,10,11,14,1,7,6,0,8,13 }
        },
        {
            { 4,11,2,14,15,0,8,13,3,12,9,7,5,10,6,1 },
            { 13,0,11,7,4,9,1,10,14,3,5,12,2,15,8,6},
            { 1,4,11,13,12,3,7,14,10,15,6,8,0,5,9,2 },
            { 6,11,13,8,1,4,10,7,9,5,0,15,14,2,3,12 }
        },
        {
            { 13,2,8,4,6,15,11,1,10,9,3,14,5,0,12,7 },
            { 1,15,13,8,10,3,7,4,12,5,6,11,0,14,9,2},
            { 7,11,4,1,9,12,14,2,0,6,10,13,15,3,5,8 },
            { 2,1,14,7,4,10,8,13,15,12,9,0,3,5,6,11 }
        }
            };

        public static int[] pBlock = {
                                    16,7,20,21,29,12,28,17,
                                    1,15,23,26,5,18,31,10,
                                    2,8,24,14,32,27,3,9,
                                    19,13,30,6,22,11,4,25
                                    };
        public static int[] inverse_p = new int[64] {
                40,8,48,16,56,24,64,32,
                39,7,47,15,55,23,63,31,
                38,6,46,14,54,22,62,30,
                37,5,45,13,53,21,61,29,
                36,4,44,12,52,20,60,28,
                35,3,43,11,51,19,59,27,
                34,2,42,10,50,18,58,26,
                33,1,41,9,49,17,57,25
            };

        public static string[] K_PC2 = new string[17];



        public static string shifting(string s, int n)//abcdef   //bcdea
        {
            string ss = s + s;
            string res = ss.Substring(n, s.Length);
            return res;
        }

        public static void GenerateKey(string key)
        {
            string binarystring = Convert.ToString(Convert.ToInt64(key, 16), 2).PadLeft(4, '0');

            if (binarystring.Length < 64)
            {
                for (int i = 64 - binarystring.Length; i > 0; i--)
                {
                    binarystring = "0" + binarystring;
                }
            }

            string K_PC1 = "";
            K_PC1 = permute(pc1, 56, binarystring);
            string C0 = K_PC1.Substring(0, K_PC1.Length / 2);
            string D0 = K_PC1.Substring(K_PC1.Length / 2, K_PC1.Length / 2);




            string[] C_list = new string[17];
            string[] D_list = new string[17];

            C_list[0] = C0;
            D_list[0] = D0;
            for (int i = 1; i <= 16; i++)
            {
                if (i == 1 || i == 2 || i == 9 || i == 16)
                {
                    C_list[i] = shifting(C_list[i - 1], 1);
                    D_list[i] = shifting(D_list[i - 1], 1);
                }
                else
                {
                    C_list[i] = shifting(C_list[i - 1], 2);
                    D_list[i] = shifting(D_list[i - 1], 2);
                }
            }

            //Adding C & D together To prepare the keys for pc2

            string C_D = "";
            for (int i = 0; i < 17; i++)
            {
                C_D += C_list[i] + D_list[i];
                K_PC2[i] = C_D;
                C_D = "";
            }


            //Permutate each key from the 16 of K_PC2 on PC2
            string tmp = "";
            string tmp_key = "";
            for (int i = 1; i < 17; i++)
            {
                tmp_key = K_PC2[i];

                for (int j = 0; j < pc2.Length; j++)
                {
                    int index = pc2[j];
                    tmp += tmp_key[index - 1];
                }
                K_PC2[i] = tmp;
                tmp = "";

            }



        }

        public static string permute(int[] block, int block_size, string textTopermutate)
        {
            string text = "";
            for (int i = 0; i < block_size; i++)
            {
                text += textTopermutate[block[i] - 1];
            }
            return text;
        }


        public static int BinaryToDecimal(string text)
        {
            int res = 0;
            int counter = 0;
            for (int i = text.Length - 1; i >= 0; i--)
            {
                if (text[i] == '1')
                {
                    res += Convert.ToInt32(Math.Pow(2, counter));
                }
                counter++;

            }
            return res;
        }

        public static string Manglerfn(string Rtext, int index)
        {
            //Expanding The Right text
            string E_Rtext = permute(eTable, 48, Rtext);


            //XOR expanded Right text with Each key
            string text = "";
            text = K_PC2[index + 1];
            string newRtext = "";
            for (int i = 0; i < 48; i++)
            {
                if (text[i] == E_Rtext[i])
                {
                    newRtext += '0';
                }
                else newRtext += '1';
            }


            string nRtext = "";
            string tmp2 = "";

            //Petmutating the XOR result on SBOX to decrease its size 
            string tmp = "";
            string row = "";
            string column = "";
            int res;
            int counter = 0;
            for (int i = 0; i < 8; i++)
            {
                for (int j = 0; j < 6; j++)
                {
                    tmp += newRtext[counter];
                    counter++;
                }

                row += tmp[0];
                row += tmp[5];

                for (int j = 1; j <= 4; j++)
                {
                    column += tmp[j];
                }



                int row_no = BinaryToDecimal(row);
                int column_no = BinaryToDecimal(column);

                res = sBox[i, row_no, column_no];

                tmp2 = Convert.ToString(res, 2);
                while (tmp2.Length < 4)
                {
                    tmp2 = "0" + tmp2;
                }

                nRtext += tmp2;

                tmp2 = "";
                row = "";
                column = "";
                tmp = "";
            }

            nRtext = permute(pBlock, 32, nRtext);
            return nRtext;

        }

        public string XOR(string r, string l)
        {
            string S = "";
            for (int i = 0; i < 32; i++)
            {
                if (r[i] == l[i]) S = S + "0";
                else S = S + "1";
            }
            return S;
        }

        public static string BinaryToHexa(string text)
        {
            string hexa = "0x";
            for (int i = 0; i < 64; i += 4)
            {
                int x = BinaryToDecimal(text.Substring(i, 4));
                if (x == 10)
                    hexa += "A";
                else if (x == 11)
                    hexa += "B";
                else if (x == 12)
                    hexa += "C";
                else if (x == 13)
                    hexa += "D";
                else if (x == 14)
                    hexa += "E";
                else if (x == 15)
                    hexa += "F";
                else
                    hexa += x;
            }
            return hexa;
        }

        public override string Decrypt(string cipherText, string key)
        {
            String text;

            GenerateKey(key);

            text = Convert.ToString(Convert.ToInt64(cipherText, 16), 2).PadLeft(4, '0');


            if (text.Length < 64)
            {
                for (int i = 64 - text.Length; i > 0; i--)
                {
                    text = "0" + text;
                }
            }

            text = permute(IP, 64, text);

            string Rtext;
            string[,] plains = new string[17, 2];
            plains[16, 0] = text.Substring(0, 32);
            plains[16, 1] = text.Substring(32, 32);

            for (int i = 15; i >= 0; i--)
            {
                plains[i, 0] = plains[i + 1, 1];
                Rtext = Manglerfn(plains[i + 1, 1], i);
                plains[i, 1] = XOR(Rtext, plains[i + 1, 0]);
            }
            string R16l16 = plains[0, 1] + plains[0, 0];

            R16l16 = permute(inverse_p, 64, R16l16);

            R16l16 = BinaryToHexa(R16l16);

            Console.WriteLine(R16l16);

            return R16l16;
        }

        public override string Encrypt(string plainText, string key)
        {
            String text;


            GenerateKey(key);
            text = Convert.ToString(Convert.ToInt64(plainText, 16), 2).PadLeft(4, '0');


            if (text.Length < 64)
            {
                for (int i = 64 - text.Length; i > 0; i--)
                {
                    text = "0" + text;
                }
            }

            text = permute(IP, 64, text);

            string Rtext;
            string[,] plains = new string[17, 2];
            plains[0, 0] = text.Substring(0, 32);
            plains[0, 1] = text.Substring(32, 32);

            for (int i = 1; i <= 16; i++)
            {
                plains[i, 0] = plains[i - 1, 1];

                Rtext = Manglerfn(plains[i - 1, 1], i - 1);

                plains[i, 1] = XOR(Rtext, plains[i - 1, 0]);
            }
            string R16l16 = plains[16, 1] + plains[16, 0];

            R16l16 = permute(inverse_p, 64, R16l16);

            R16l16 = BinaryToHexa(R16l16);

            Console.WriteLine(R16l16);

            return R16l16;
        }
    }
}