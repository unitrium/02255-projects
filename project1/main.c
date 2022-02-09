#include <iostream>
#include <vector>
#include <string>

using namespace std;

int main()
{
    vector<string> msg{"Hello", "C++", "World", "from", "VS Code", "and the C++ extension!"};

    for (const string &word : msg)
    {
        cout << word << " ";
    }
    cout << endl;
}

void delta_sets(char[] input, char[][] output, int active_index = 0)
{
    char hex_string[20];
    for (int i = 0; i < active_index; i++)
    {
        for (int j = 0; j < 256; j++)
        {
            output[j][i] = input[i];
        }
    }
    for (int j = 0; j < 256; j++)
    {
        }
}