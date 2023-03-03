using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class PlayFair : ICryptographic_Technique<string, string>
    {
        struct pair{
            public int x;
            public int y;
        }
        static char[,] matrix;
        static pair[] position;
        public static char[,] createMatrix(string key)
        {
            char[,] matrix = new char[5, 5];
            bool[] visited = new bool[26];
            int index = 0, itr = 0;
            for (int i = 0; i < 5; i++)
            {
                for (int j = 0; j < 5; j++)
                {
                    while (index < key.Length && visited[key[index] - 'a']) index++;
                    if (index < key.Length)
                    {
                        matrix[i, j] = key[index];
                        if (key[index] == 'i' || key[index] == 'j')
                        {
                            visited['i' - 'a'] = true;
                            visited['j' - 'a'] = true;
                        }
                        visited[key[index] - 'a'] = true;
                        position[key[index] - 'a'].x = i;
                        position[key[index] - 'a'].y = j;
                        index++;
                        continue;
                    }
                    while (itr < 26 && visited[itr]) itr++;
                    if (itr < 26)
                    {
                        matrix[i, j] = (char)('a' + itr);
                        if (itr == 'i' - 'a')
                        {
                            visited['i' - 'a'] = true;
                            visited['j' - 'a'] = true;
                        }
                        position[itr].x = i;
                        position[itr].y = j;
                        visited[itr] = true;
                    }
                }
            }
            return matrix;
        }
        public static string reverseSemgment(char a, char b, int d = 1)
        {
            pair aCorditnate = position[a - 'a'];
            pair bCorditnate = position[b - 'a'];
            char f, s;

            if (aCorditnate.x == bCorditnate.x)
            {
                f = matrix[aCorditnate.x, ((aCorditnate.y + d) % 5 + 5) % 5];
                s = matrix[bCorditnate.x, ((bCorditnate.y + d) % 5 + 5) % 5];
            }

            else if (aCorditnate.y == bCorditnate.y)
            {
                f = matrix[(aCorditnate.x + d + 5) % 5, aCorditnate.y];
                s = matrix[(bCorditnate.x + d + 5) % 5, bCorditnate.y];
            }

            else
            { 
                f = matrix[aCorditnate.x, bCorditnate.y];
                s = matrix[bCorditnate.x, aCorditnate.y];   
            }
            return ""+f+s;
        }
        public string Decrypt(string cipherText, string key)
        {
            string plainText = "";
            cipherText = cipherText.ToLower();
            position = new pair[26];
            matrix = createMatrix(key);
            for (int i = 0; i < cipherText.Length - 1; i += 2)
            {
                char a = cipherText[i];
                char b = cipherText[i + 1];
                string res = reverseSemgment(a, b, -1);
                if (plainText != "" && plainText[plainText.Length - 1] == 'x' && res[0] == plainText[plainText.Length - 2])
                    plainText = plainText.Remove(plainText.Length - 1);
                plainText += res;
            }
            if (plainText[plainText.Length - 1] == 'x') plainText = plainText.Remove(plainText.Length - 1);
            return plainText;
        }
        public string Encrypt(string plainText, string key)
        {
            string cipherText = "";
            position = new pair[26];
            matrix = createMatrix(key);

            for (int i = 0; i < plainText.Length; i++)
            {
                char a = plainText[i];
                char b = 'x';
                if (
                i + 1 < plainText.Length && 
                plainText[i + 1] != a && 
                
                // to void "ij" & "ji" 
                // to divide ("ix", "jx"), ("jx", "ix")
                
                !((a=='i'||a=='j')&&(plainText[i+1]=='i'||plainText[i + 1]=='j'))
                
                ){
                    b = plainText[i + 1];
                    i++;
                }
                cipherText += reverseSemgment(a, b);
            }
            return cipherText;
        }
    
    }
}
