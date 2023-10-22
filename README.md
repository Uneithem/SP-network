# SP-network

In main.py you can see encryption and decryption algoritms using SP-network. 

In short: S-box is a substitution block, which substitutes characters using spreadsheet (I've implemented it with dictionary)

P-box is a permutation block, it works next way for 16 blocks: blocks with indices 2-8 are replaced at place (i^2(mod17)), where i is position of block in original set
Blocks 1 and 9-16 are placed in order that was made in a random way.

Same goes for 12 blocks and 9 blocks. There's different amount of blocks because each S-box decreases amount of bits by 2 in each block, therefore, string length decreases by 2*(number of blocks) for each iteration.

Reversed algorithm for P-box is quite simple to build, having the map of permutations.

Substitution block, however, is hard to reverse. Firstly, we need reversed substitution spreadsheet, where intersection of each row and column are characters that were substituted by number in first column of the corresponding row and with key that is first row of the corresponding column.

However, each key value has all possible sets of output values, therefore we'll bump into 4 possible values for input. And that's only for the first block. Therefore, just the reverse of s-box is not enough and we need something that will actually help us find one-to-one mapping between outputs and inputs.

I've tried to implement it using control sums, but I believe that it gives off way too much information about original string and, in addition to that, the redesign of sbox is necessary, as it's possible to find two values in each row that have the same sum (sometimes even 4 elements with the same sum can be encountered)

In addition to that, secure S-boxes do not use sums, which even strengthens my impression that it's way too insecure to use sums.
