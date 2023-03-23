using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class PlayFair : ICryptographic_Technique<string, string>
    {
        public static int x1 = -1, y1 = -1, x2 = -1, y2 = -1;

        static int[] position(char[,] matrix, char c)
        {
            int[] result = {-1,-1};
            if(c == 'j')
                c = 'i';
            for(int i=0 ; i < 5 ; i++)
            {
                for(int j=0 ; j < 5 ; j++)
                {
                    if(matrix[i,j] == c)
                    {
                        result[0] = i;
                        result[1] = j;
                        return result;
                    }
                }
            }
            return result;
        }
        //our swap function
        static void swap(ref int x,ref int y)
        {
            int temp = y;
            y = x;
            x = temp;
        }
        //get position of the first letter in the Matrix
        static void position1(char [,] arr,char c)
        {
            if (c == 'j')
                c = 'i';
            for (int i = 0; i < 5; i++)
            {
                for (int j = 0; j < 5; j++)
                {
                    if (c == arr[i, j])
                    {
                        x1 = i;
                        y1 = j;
                    }
                }
            }
        }
        //get position of the second letter in the Matrix
        static void position2(char[,] arr, char c)
        {
            if (c == 'j')
                c = 'i';
            for (int i = 0; i < 5; i++)
            {
                for (int j = 0; j < 5; j++)
                {
                    if (c == arr[i, j])
                    {
                        x2 = i;
                        y2 = j;
                    }
                }
            }
        }
        //search the element while filling the Matrix
         static bool isFound(char [,] arr,char c, int size)
        {
            for (int i = 0; i < 5; i++)
            {
                for (int j = 0; j < 5; j++)
                {
                    if (arr[i, j] == c)
                        return true;
                    if (size == 0)
                        break;
                    size--;
                }
                if (size == 0)
                    break;
            }
            return false;
        }

        //Encryption function (PlayFair)
        public string Encrypt(string plainText, string key)
        {
            //throw new NotImplementedException();

            //handle the plaintext with 'x' letter in particular cases
            plainText = plainText.ToLower();
            for (int i = 0; i < plainText.Length - 2; i++)
            { 
                if (plainText[i] == plainText[i + 1] && i % 2 == 0)
                {
                    plainText = plainText.Insert(i+1, "x");
                }
            }

            //put 'x' letter @ the end of list to complete pairs
            if (plainText.Length % 2 != 0)
                plainText = plainText + "x";
            
            //putting key characters in a list to handel letter dublicates
            key.ToLower();
            LinkedList<char> keyList = new LinkedList<char>();
            for (int i = 0; i < key.Length; i++)
            {
                if (!keyList.Contains(key[i]))
                {
                    keyList.AddLast(key[i]);
                }
            }

            //create 5x5 Matrix
            char[,] array = new char[5, 5];
            //initializing the array with '*'
            for (int i = 0; i < 5; i++)
            {
                for (int j = 0; j < 5; j++)
                {
                    array[i, j] = '*';
                }
            }
            //filling the Matrix with key characters
            int it = 0;
            for (int i = 0; i < 5; i++)
            {
                for (int j = 0; j < 5; j++)
                {
                    if (it < keyList.Count)
                    {
                        char val = keyList.ElementAt<char>(it);
                        array[i, j] = val;
                        it++;
                    }
                    else
                    {
                        break;
                    }

                }
            }
            //fill the rest of matrix with alphabetic letters
            char Fill = 'a';
            int size = 1;
            for (int i = 0; i < 5; i++)
            {
                for (int j = 0; j < 5; j++)
                {
                    if (size > keyList.Count)
                    {
                        if (Fill == 'j')
                            Fill++;
                        if (!isFound(array, Fill, keyList.Count))
                            array[i, j] = Fill;
                        else
                            j--;
                        Fill++;
                    }
                    size++;
                }
            }
            //generate the cipher text
            char a, b;
            int itt = 0; //iterator
            LinkedList<char> cipherList = new LinkedList<char>();
            while (itt < plainText.Length -1)
            { 
                x1 = -1; y1 = -1; x2 = -1; y2 = -1;
                
                a = plainText[itt];
                b = plainText[itt + 1];
                position1(array, a);
                position2(array, b);

                if(y1 == y2)
                {
                    x1 = (x1 + 1) % 5;
                    x2 = (x2 + 1) % 5;
                    cipherList.AddLast(array[x1, y1]);
                    cipherList.AddLast(array[x2, y2]);
                }
                else if(x1 == x2)
                { 
                    y1 = (y1 + 1) % 5;
                    y2 = (y2 + 1) % 5;
                    cipherList.AddLast(array[x1, y1]);
                    cipherList.AddLast(array[x2, y2]);
                }
                else
                {
                    swap(ref y1, ref y2);
                    cipherList.AddLast(array[x1, y1]);
                    cipherList.AddLast(array[x2, y2]);
                }
                itt+=2;
            }
            string cipherText = new string(cipherList.ToArray());
            return cipherText;
        }

        public string Decrypt(string cipherText, string key)
        {
            //throw new NotImplementedException();

            ////////////////....HANDLING KEY.....////////////////
            key = key.ToLower();
            //remove duplicates
            List<char> keyList = new List<char>();
            for(int i=0 ; i < key.Length ; i++)
            {
                if(!keyList.Contains(key[i]))
                    keyList.Add(key[i]);
            }
            //create matrix 5x5
            char[,] matrix = new char[5,5];
            int keyListIterator = 0;
            for (int i = 0; i < 5; i++)
			{
                for (int j = 0; j < 5; j++)
			    {
                    if(keyListIterator == keyList.Count)
                        break;
                    else
                        matrix[i,j] = keyList[keyListIterator];
                    keyListIterator++;
			    }
                if(keyListIterator == keyList.Count)
                        break;
			}
            //fill matrix
            char fill = 'a';
            for (int i = 0; i < 5; i++)
			{
                for (int j = 0; j < 5; j++)
			    {
                    if(keyListIterator < 1)
                    {
                        if(fill == 'j')
                            fill++;
                        if(keyList.Contains(fill))
                            j--;
                        else
                            matrix[i,j] = fill;
                        fill++;
                    }
                    else
                        keyListIterator--;
			    }
			}
            /////////////////......HANDLING CIPHER_TEXT......///////////
            cipherText = cipherText.ToLower();
            char a,b;
            string plainText = "";
            for(int i = 0 ; i < cipherText.Length ; i+=2)
            {
                a = cipherText[i];
                b = cipherText[i+1];
                int [] positionX = position(matrix,a);
                int x1 = positionX[0];
                int y1 = positionX[1];
                int [] positionY = position(matrix,b);
                int x2 = positionY[0];
                int y2 = positionY[1];

                if(y1 == y2)
                {
                    x1 = ((x1 - 1)+5) % 5;
                    x2 = ((x2 - 1)+5) % 5;
                    plainText = plainText + matrix[x1,y1];
                    plainText = plainText + matrix[x2,y2];
                }
                else if(x1 == x2)
                {
                    y1 = ((y1 - 1)+5) % 5;
                    y2 = ((y2 - 1)+5) % 5;
                    plainText = plainText + matrix[x1,y1];
                    plainText = plainText + matrix[x2,y2];
                }
                else
                {
                    swap(ref y1, ref y2);
                    plainText = plainText + matrix[x1,y1];
                    plainText = plainText + matrix[x2,y2];
                }
            }
            string finalPlain = "";
            finalPlain += plainText[0];
            for (int i = 1; i < plainText.Length - 1; i++)
            {
                if (plainText[i] == 'x' && i % 2 != 0)
                {
                    if (plainText[i - 1] != plainText[i + 1])
                        finalPlain += plainText[i];
                }
                else
                    finalPlain += plainText[i];
            }
            if (plainText[plainText.Length - 1] != 'x')
                finalPlain += plainText[plainText.Length - 1];
            return finalPlain;



        }

    }
}